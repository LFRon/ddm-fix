/*
 * Session process wrapper
 * Copyright (C) 2023-2026 UnionTech Software Technology Co., Ltd.
 * Copyright (C) 2015 Pier Luigi Fiorini <pierluigi.fiorini@gmail.com>
 * Copyright (C) 2014 Martin Bříza <mbriza@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <QCoreApplication>
#include <QSocketNotifier>

#include "Auth.h"
#include "Configuration.h"
#include "TreelandConnector.h"
#include "UserSession.h"
#include "VirtualTerminal.h"
#include "XAuth.h"

#include <linux/kd.h>
#include <functional>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <fcntl.h>
#include <sched.h>
#include <termios.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>

namespace DDM {
    namespace {
        [[noreturn]] void childDie(const char *message) {
            dprintf(STDERR_FILENO, "%s\n", message);
            _exit(1);
        }

        [[noreturn]] void childDieErrno(const char *message) {
            dprintf(STDERR_FILENO, "%s: %s\n", message, strerror(errno));
            _exit(1);
        }

        void makeParentDirs(const char *filePath) {
            char dir[PATH_MAX];
            const size_t len = strnlen(filePath, sizeof(dir));
            if (len == 0 || len >= sizeof(dir))
                childDie("Invalid session log path");

            memcpy(dir, filePath, len + 1);
            char *lastSlash = strrchr(dir, '/');
            if (!lastSlash)
                return;
            if (lastSlash == dir) {
                return;
            }
            *lastSlash = '\0';

            for (char *p = dir + 1; *p; ++p) {
                if (*p != '/')
                    continue;
                *p = '\0';
                if (mkdir(dir, 0700) != 0 && errno != EEXIST)
                    childDieErrno("Failed to create session log directory");
                *p = '/';
            }
            if (mkdir(dir, 0700) != 0 && errno != EEXIST)
                childDieErrno("Failed to create session log directory");
        }
    }

    UserSession::UserSession(Auth *parent)
        : QProcess(parent) {
        setChildProcessModifier(std::bind(&UserSession::childModifier, this));
    }

    void UserSession::prepareChildContext(Display::DisplayServerType type) {
        Auth *auth = qobject_cast<Auth *>(parent());
        Q_ASSERT(auth);

        m_sessionType = type;
        m_userName = auth->user.toLocal8Bit();
        m_ttyPath = VirtualTerminal::path(auth->tty).toLocal8Bit();
        m_namespaces.clear();
        for (const QString &ns : mainConfig.Namespaces.get())
            m_namespaces << ns.toLocal8Bit();
        m_sessionLogFile = (type == Display::X11
                            ? mainConfig.X11.SessionLogFile.get()
                            : mainConfig.Wayland.SessionLogFile.get()).toLocal8Bit();
        m_xauthFd = m_xauthFile.handle();
    }

    void UserSession::start(const QString &command,
                            Display::DisplayServerType type,
                            const QByteArray &cookie) {
        QProcessEnvironment env = processEnvironment();

        switch (type) {
        case Display::Treeland: {
            setProgram(mainConfig.Single.SessionCommand.get());
            setArguments(QStringList{ command });
            qInfo() << "Starting Treeland session:" << program() << command;
            prepareChildContext(type);
            QProcess::start();
            closeWriteChannel();
            closeReadChannel(QProcess::StandardOutput);
            return;
        }
        case Display::X11: {
            if (cookie.isEmpty()) {
                qCritical() << "Can't start X11 session with empty auth cookie";
                return;
            }
            // Create the Xauthority file
            // Place it into /tmp, which is guaranteed to be read/writeable by
            // everyone while having the sticky bit set to avoid messing with
            // other's files.
            m_xauthFile.setFileTemplate(QStringLiteral("/tmp/xauth_XXXXXX"));

            if (!m_xauthFile.open()) {
                qCritical() << "Could not create the Xauthority file";
                return;
            }

            QString display = env.value(QStringLiteral("DISPLAY"));

            if (!XAuth::writeCookieToFile(display, m_xauthFile.fileName(), cookie)) {
                qCritical() << "Failed to write the Xauthority file";
                m_xauthFile.close();
                return;
            }

            env.insert(QStringLiteral("XAUTHORITY"), m_xauthFile.fileName());
            setProcessEnvironment(env);

            qInfo() << "Starting X11 user session:" << command;
            setProgram(mainConfig.X11.SessionCommand.get());
            setArguments(QStringList{ command });
            prepareChildContext(type);
            QProcess::start();
            return;
        }
        case Display::Wayland: {
            setProgram(mainConfig.Wayland.SessionCommand.get());
            setArguments(QStringList{ command });
            qInfo() << "Starting Wayland user session:" << program() << command;
            prepareChildContext(type);
            QProcess::start();
            closeWriteChannel();
            closeReadChannel(QProcess::StandardOutput);
            return;
        }
        default: {
            qCritical() << "Unable to run user session: unknown session type";
        }
        }
    }

    qint64 UserSession::startDirect(const QString &command,
                                    Display::DisplayServerType type,
                                    const QByteArray &cookie) {
        if (type != Display::Treeland) {
            qCritical() << "Direct user session start only supports Treeland sessions";
            return -1;
        }
        Q_UNUSED(cookie)

        prepareChildContext(type);

        QList<QByteArray> argvStorage{
            mainConfig.Single.SessionCommand.get().toLocal8Bit(),
            command.toLocal8Bit(),
        };
        QList<char *> argv;
        for (QByteArray &arg : argvStorage)
            argv << arg.data();
        argv << nullptr;

        QList<QByteArray> envStorage;
        for (const QString &entry : processEnvironment().toStringList())
            envStorage << entry.toLocal8Bit();
        QList<char *> envp;
        for (QByteArray &entry : envStorage)
            envp << entry.data();
        envp << nullptr;

        qInfo() << "Starting Treeland session:" << argvStorage.first() << command;
        const pid_t pid = fork();
        switch (pid) {
        case -1:
            qWarning() << "Failed to fork Treeland session:" << strerror(errno);
            return -1;
        case 0:
            childModifier();
            execve(argv[0], argv.data(), envp.data());
            childDieErrno("Failed to exec Treeland session");
        default:
            if (m_xauthFile.isOpen())
                m_xauthFile.close();
            m_xauthFd = -1;
            return pid;
        }
    }

    void UserSession::stop()
    {
        if (state() != QProcess::NotRunning) {
            terminate();
            if (!waitForFinished(60000)) {
                kill();
                if (!waitForFinished(5000)) {
                    qWarning() << "Could not fully finish the process" << program();
                }
            }
        } else {
            Q_EMIT finished(1);
        }
    }

    void UserSession::childModifier() {
        // When the display server is part of the session, we leak the VT into
        // the session as stdin so that it stays open without races
        if (m_sessionType != Display::X11) {
            // open VT and get the fd
            int vtFd = ::open(m_ttyPath.constData(), O_RDWR | O_NOCTTY);

            // when this is true we'll take control of the tty
            bool takeControl = false;

            if (vtFd > 0) {
                dup2(vtFd, STDIN_FILENO);
                ::close(vtFd);
                takeControl = true;
            } else {
                int stdinFd = ::open("/dev/null", O_RDWR);
                dup2(stdinFd, STDIN_FILENO);
                ::close(stdinFd);
            }

            // set this process as session leader
            if (setsid() < 0) {
                childDieErrno("Failed to create a new session");
            }

            // take control of the tty
            if (takeControl) {
                if (ioctl(STDIN_FILENO, TIOCSCTTY, 1) < 0) {
                    childDieErrno("Failed to take control of tty");
                }
                if (ioctl(STDIN_FILENO, KDSKBMODE, K_OFF) == -1) {
                    childDieErrno("Failed to set keyboard mode to K_OFF");
                }
            }
        }

        // enter Linux namespaces
        for (const QByteArray &ns: m_namespaces) {
            int fd = ::open(ns.constData(), O_RDONLY);
            if (fd < 0)
                childDieErrno("Failed to open namespace");
            if (setns(fd, 0) != 0)
                childDieErrno("Failed to enter namespace");
            ::close(fd);
        }

        // switch user
        struct passwd pw;
        struct passwd *rpw;
        long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize == -1)
            bufsize = 16384;
        char *buffer = static_cast<char *>(malloc(bufsize));
        if (!buffer)
            childDie("Could not allocate passwd buffer");
        int err = getpwnam_r(m_userName.constData(), &pw, buffer, bufsize, &rpw);
        if (rpw == NULL) {
            if (err != 0)
                errno = err;
            childDieErrno("Failed to resolve session user");
        }

        if (m_xauthFd != -1 && fchown(m_xauthFd, pw.pw_uid, pw.pw_gid) != 0)
            childDieErrno("Failed to change Xauthority owner");

        if (setgid(pw.pw_gid) != 0)
            childDieErrno("Failed to set session gid");

        // fetch ambient groups from PAM's environment;
        // these are set by modules such as pam_groups.so
        int n_pam_groups = getgroups(0, NULL);
        gid_t *pam_groups = NULL;
        if (n_pam_groups > 0) {
            pam_groups = static_cast<gid_t *>(malloc(n_pam_groups * sizeof(gid_t)));
            if (!pam_groups)
                childDie("Could not allocate PAM groups");
            if ((n_pam_groups = getgroups(n_pam_groups, pam_groups)) == -1) {
                childDieErrno("Failed to fetch supplemental PAM groups");
            }
        } else {
            n_pam_groups = 0;
        }

        // fetch session's user's groups
        int n_user_groups = 0;
        gid_t *user_groups = NULL;
        if (-1 == getgrouplist(pw.pw_name, pw.pw_gid,
                                NULL, &n_user_groups)) {
            user_groups = static_cast<gid_t *>(malloc(n_user_groups * sizeof(gid_t)));
            if (!user_groups)
                childDie("Could not allocate user groups");
            if ((n_user_groups = getgrouplist(pw.pw_name,
                                               pw.pw_gid, user_groups,
                                               &n_user_groups)) == -1 ) {
                childDie("Failed to fetch user groups");
            }
        }

        // set groups to concatenation of PAM's ambient
        // groups and the session's user's groups
        int n_groups = n_pam_groups + n_user_groups;
        if (n_groups > 0) {
            gid_t *groups = static_cast<gid_t *>(malloc(n_groups * sizeof(gid_t)));
            if (!groups)
                childDie("Could not allocate combined groups");
            memcpy(groups, pam_groups, (n_pam_groups * sizeof(gid_t)));
            memcpy((groups + n_pam_groups), user_groups,
                   (n_user_groups * sizeof(gid_t)));

            // setgroups(2) handles duplicate groups
            if (setgroups(n_groups, groups) != 0)
                childDieErrno("Failed to set supplemental groups");
            free(groups);
        }
        free(pam_groups);
        free(user_groups);

        if (setuid(pw.pw_uid) != 0)
            childDieErrno("Failed to set session uid");

        if (chdir(pw.pw_dir) != 0)
            childDieErrno("Failed to change to user home directory");

        //we cannot use setStandardError file as this code is run in the child process
        //we want to redirect after we setuid so that the log file is owned by the user

        // determine stderr log file based on session type
        char sessionLog[PATH_MAX];
        if (!m_sessionLogFile.isEmpty() && m_sessionLogFile.constData()[0] == '/') {
            if (snprintf(sessionLog, sizeof(sessionLog), "%s", m_sessionLogFile.constData()) >= static_cast<int>(sizeof(sessionLog)))
                childDie("Session log path is too long");
        } else if (snprintf(sessionLog, sizeof(sessionLog), "%s/%s", pw.pw_dir, m_sessionLogFile.constData()) >= static_cast<int>(sizeof(sessionLog))) {
            childDie("Session log path is too long");
        }

        makeParentDirs(sessionLog);

        //swap the stderr pipe of this subprcess into a file
        int fd = ::open(sessionLog, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd >= 0) {
            dup2 (fd, STDERR_FILENO);
            ::close(fd);
        } else {
            dprintf(STDERR_FILENO, "Could not open stderr to %s: %s\n", sessionLog, strerror(errno));
        }

        //redirect any stdout to /dev/null
        fd = ::open("/dev/null", O_WRONLY);
        if (fd >= 0) {
            dup2 (fd, STDOUT_FILENO);
            ::close(fd);
        } else {
            dprintf(STDERR_FILENO, "Could not redirect stdout: %s\n", strerror(errno));
        }

        free(buffer);
    }
}
