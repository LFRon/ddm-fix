// Copyright (C) 2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include "Auth.h"

#include "UserSession.h"

#include "DaemonApp.h"
#include "Login1Manager.h"
#include "Login1Session.h"
#include "SignalHandler.h"
#include "VirtualTerminal.h"

#include <QCoreApplication>
#include <QDataStream>
#include <QFile>

#include <pwd.h>
#include <security/pam_appl.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <utmp.h>
#include <utmpx.h>

namespace DDM {
    namespace {
        bool s_runningSessionHelper = false;
        int s_sessionHelperLifecycleFd = -1;
    }

    ///////////////////////////
    // utmp helper functions //
    ///////////////////////////

    void Auth::utmpLogin(bool success) {
        struct utmpx entry { };
        struct timeval tv;

        entry.ut_type = USER_PROCESS;
        entry.ut_pid = sessionPid;

        // ut_line: vt
        if (tty > 0)
            strncpy(entry.ut_line, QStringLiteral("tty%1").arg(tty).toLocal8Bit().constData(), sizeof(entry.ut_line) - 1);

        // ut_host: displayName
        if (!display.isEmpty())
            strncpy(entry.ut_host, display.toLocal8Bit().constData(), sizeof(entry.ut_host) - 1);

        // ut_user: user
        strncpy(entry.ut_user, user.toLocal8Bit().constData(), sizeof(entry.ut_user) -1);

        gettimeofday(&tv, NULL);
        entry.ut_tv.tv_sec = tv.tv_sec;
        entry.ut_tv.tv_usec = tv.tv_usec;

        // write to utmp
        setutxent();
        if (!pututxline (&entry))
            qWarning() << "Failed to write utmpx: " << strerror(errno);
        endutxent();

        // append to failed login database btmp
        if (!success) {
            updwtmpx("/var/log/btmp", &entry);
        } else {
            // append to wtmp
            updwtmpx("/var/log/wtmp", &entry);
        }
    }

    void Auth::utmpLogout() {
        struct utmpx entry { };
        struct timeval tv;

        entry.ut_type = DEAD_PROCESS;
        entry.ut_pid = sessionPid;

        // ut_line: vt
        if (tty > 0)
            strncpy(entry.ut_line, QStringLiteral("tty%1").arg(tty).toLocal8Bit().constData(), sizeof(entry.ut_line) - 1);

        // ut_host: displayName
        if (!display.isEmpty())
            strncpy(entry.ut_host, display.toLocal8Bit().constData(), sizeof(entry.ut_host) - 1);

        gettimeofday(&tv, NULL);
        entry.ut_tv.tv_sec = tv.tv_sec;
        entry.ut_tv.tv_usec = tv.tv_usec;

        // write to utmp
        setutxent();
        if (!pututxline (&entry))
            qWarning() << "Failed to write utmpx: " << strerror(errno);
        endutxent();

        // append to wtmp
        updwtmpx("/var/log/wtmp", &entry);
    }

    ///////////////////////////////
    // PAM conversation function //
    ///////////////////////////////

    /** PAM conversation function */
    static int converse(int num_msg,
                        const struct pam_message **msg,
                        struct pam_response **resp,
                        void *secret_ptr) {
        *resp = (struct pam_response *) calloc(num_msg, sizeof(struct pam_response));
        if (!*resp)
            return PAM_BUF_ERR;

        // We only handle secret (password) sending here, which is
        // prompt by PAM_PROMPT_ECHO_OFF.  Message types (error/info)
        // are just logged.
        //
        // Prompts with PAM_PROMPT_ECHO_ON (most likely asking for
        // username) are not expected, since we required username is
        // set before.
        for (int i = 0; i < num_msg; ++i) {
            switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                resp[i]->resp = strdup(*static_cast<const char **>(secret_ptr));
                resp[i]->resp_retcode = 0;
                break;
            case PAM_ERROR_MSG:
                qWarning() << "[Converse] Error message:" << msg[i]->msg;
                resp[i]->resp = nullptr;
                resp[i]->resp_retcode = 0;
                break;
            case PAM_TEXT_INFO:
                qInfo() << "[Converse] Info message:" << msg[i]->msg;
                resp[i]->resp = nullptr;
                resp[i]->resp_retcode = 0;
                break;
            default:
                qCritical("[Converse] Unsupported message style %d: %s", msg[i]->msg_style, msg[i]->msg);
                for (int j = 0; j < i; j++) {
                    free(resp[j]->resp);
                    resp[j]->resp = nullptr;
                }
                free(*resp);
                *resp = nullptr;
                return PAM_CONV_ERR;
            }
        }
        return PAM_SUCCESS;
    }

    /////////////////////////
    // Auth implementation //
    /////////////////////////

    class AuthPrivate : public QObject {
        Q_OBJECT
    public:
        AuthPrivate(Auth *parent)
            : QObject(parent)
            , secretPtr(new const char *)
            , conv({ converse, static_cast<void *>(secretPtr) }) {
            *secretPtr = nullptr;
        }

        ~AuthPrivate() {
            delete secretPtr;
        }

        pam_handle_t *handle{ nullptr };
        const char **secretPtr{};
        pam_conv conv{};
        int ret{};
        QByteArray secret;
        bool helperSession{ false };
    };

    Auth::Auth(QObject *parent, QString user)
        : QObject(parent)
        , user(user)
        , d(new AuthPrivate(this)) {}

    Auth::~Auth() {
        if (sessionOpened) {
            delete m_notifier;
            if (sessionPid > 0)
                kill(sessionPid, SIGTERM);
            if (sessionLeaderPid > 0)
                kill(sessionLeaderPid, SIGTERM);
            if (!d->helperSession)
                closeSession();
            utmpLogout();
        }
        if (d->handle) {
            d->ret = pam_end(d->handle, d->ret);
            if (d->ret != PAM_SUCCESS)
                qWarning() << "[Auth] PAM handle end with error!";
        }
        qInfo() << "[Auth] Auth for user" << user << "ended.";
    }

#define CHECK_RET_AUTH                                                           \
    if (d->ret != PAM_SUCCESS) {                                                 \
        qWarning() << "[Auth] Authenticate:" << pam_strerror(d->handle, d->ret); \
        utmpLogin(false);                                                        \
        return false;                                                            \
    }
    bool Auth::authenticate(const QByteArray &secret) {
        Q_ASSERT(!user.isEmpty());

        qInfo() << "[Auth] Starting...";
        d->ret = pam_start("ddm", user.toLocal8Bit().constData(), &d->conv, &d->handle);
        CHECK_RET_AUTH

        qInfo() << "[Auth] Authenticating user" << user;

        // Set the secret, authenticate, then clear the secret
        // immediately to avoid leak
        *d->secretPtr = secret.constData();
        d->ret = pam_authenticate(d->handle, 0);
        *d->secretPtr = nullptr;

        CHECK_RET_AUTH
        qInfo() << "[Auth] Authenticated.";

        d->ret = pam_acct_mgmt(d->handle, 0);
        CHECK_RET_AUTH

        d->secret = secret;
        authenticated = true;
        return true;
    }

    struct SessionHelperRequest {
        QString user;
        QByteArray secret;
        QString command;
        QStringList environment;
        QByteArray cookie;
        QString display;
        int type = Display::Wayland;
        int tty = 0;
    };

    struct SessionHelperResponse {
        int xdgSessionId = -1;
        qint64 sessionPid = -1;
    };

    static QDataStream &operator<<(QDataStream &stream, const SessionHelperRequest &request) {
        stream << request.user
               << request.secret
               << request.command
               << request.environment
               << request.cookie
               << request.display
               << request.type
               << request.tty;
        return stream;
    }

    static QDataStream &operator>>(QDataStream &stream, SessionHelperRequest &request) {
        stream >> request.user
               >> request.secret
               >> request.command
               >> request.environment
               >> request.cookie
               >> request.display
               >> request.type
               >> request.tty;
        return stream;
    }

    static QDataStream &operator<<(QDataStream &stream, const SessionHelperResponse &response) {
        stream << response.xdgSessionId << response.sessionPid;
        return stream;
    }

    static QDataStream &operator>>(QDataStream &stream, SessionHelperResponse &response) {
        stream >> response.xdgSessionId >> response.sessionPid;
        return stream;
    }

    static bool readAllFromFd(int fd, QByteArray *data) {
        data->clear();
        char buffer[4096];
        while (true) {
            const ssize_t bytes = read(fd, buffer, sizeof(buffer));
            if (bytes > 0) {
                data->append(buffer, qsizetype(bytes));
                continue;
            }
            if (bytes == 0)
                return true;
            if (errno == EINTR)
                continue;
            return false;
        }
    }

    static bool writeAllToFd(int fd, const QByteArray &data) {
        qsizetype written = 0;
        while (written < data.size()) {
            const ssize_t bytes = write(fd, data.constData() + written, size_t(data.size() - written));
            if (bytes > 0) {
                written += bytes;
                continue;
            }
            if (bytes < 0 && errno == EINTR)
                continue;
            return false;
        }
        return true;
    }

    static QByteArray serializeRequest(const SessionHelperRequest &request) {
        QByteArray data;
        QDataStream stream(&data, QIODevice::WriteOnly);
        stream << request;
        return data;
    }

    static QByteArray serializeResponse(const SessionHelperResponse &response) {
        QByteArray data;
        QDataStream stream(&data, QIODevice::WriteOnly);
        stream << response;
        return data;
    }

    static std::optional<SessionHelperResponse> deserializeResponse(const QByteArray &data) {
        SessionHelperResponse response;
        QDataStream stream(data);
        stream >> response;
        if (stream.status() != QDataStream::Ok)
            return std::nullopt;
        return response;
    }

    static std::optional<SessionHelperRequest> deserializeRequest(const QByteArray &data) {
        SessionHelperRequest request;
        QDataStream stream(data);
        stream >> request;
        if (stream.status() != QDataStream::Ok)
            return std::nullopt;
        return request;
    }

    int Auth::openSessionInHelperProcess(const QString &command,
                                         const QProcessEnvironment &env,
                                         const QByteArray &cookie,
                                         QByteArray secret) {
        int requestPipe[2];
        int responsePipe[2];
        int lifecyclePipe[2];
        if (pipe(requestPipe) == -1) {
            qWarning() << "[Auth] helper pipe failed:" << strerror(errno);
            return -1;
        }
        if (pipe(responsePipe) == -1) {
            qWarning() << "[Auth] helper pipe failed:" << strerror(errno);
            close(requestPipe[0]);
            close(requestPipe[1]);
            return -1;
        }
        if (pipe(lifecyclePipe) == -1) {
            qWarning() << "[Auth] helper pipe failed:" << strerror(errno);
            close(requestPipe[0]);
            close(requestPipe[1]);
            close(responsePipe[0]);
            close(responsePipe[1]);
            return -1;
        }

        const pid_t helperPid = fork();
        switch (helperPid) {
        case -1:
            qWarning() << "[Auth] helper fork failed:" << strerror(errno);
            close(requestPipe[0]);
            close(requestPipe[1]);
            close(responsePipe[0]);
            close(responsePipe[1]);
            close(lifecyclePipe[0]);
            close(lifecyclePipe[1]);
            return -1;
        case 0: {
            dup2(requestPipe[0], STDIN_FILENO);
            dup2(responsePipe[1], STDOUT_FILENO);
            close(requestPipe[0]);
            close(requestPipe[1]);
            close(responsePipe[0]);
            close(responsePipe[1]);
            close(lifecyclePipe[0]);

            const QByteArray lifecycleFd = QByteArray::number(lifecyclePipe[1]);
            setenv("DDM_SESSION_HELPER_LIFECYCLE_FD", lifecycleFd.constData(), 1);
            const QByteArray program = QFile::encodeName(QCoreApplication::applicationFilePath());
            execl(program.constData(), program.constData(), "--session-helper", nullptr);
            _exit(127);
        }
        default:
            close(requestPipe[0]);
            close(responsePipe[1]);
            close(lifecyclePipe[1]);
            break;
        }

        SessionHelperRequest request;
        request.user = user;
        request.secret = secret;
        request.command = command;
        request.environment = env.toStringList();
        request.cookie = cookie;
        request.display = display;
        request.type = type;
        request.tty = tty;

        const QByteArray requestData = serializeRequest(request);
        secret.fill('\0');
        if (!writeAllToFd(requestPipe[1], requestData)) {
            qWarning() << "[Auth] Failed to write session helper request:" << strerror(errno);
            close(requestPipe[1]);
            close(responsePipe[0]);
            close(lifecyclePipe[0]);
            return -1;
        }
        close(requestPipe[1]);

        QByteArray responseData;
        if (!readAllFromFd(responsePipe[0], &responseData)) {
            qWarning() << "[Auth] Failed to read session helper response:" << strerror(errno);
            close(responsePipe[0]);
            close(lifecyclePipe[0]);
            return -1;
        }
        close(responsePipe[0]);

        auto response = deserializeResponse(responseData);
        if (!response.has_value()) {
            qWarning() << "[Auth] Invalid session helper response";
            close(lifecyclePipe[0]);
            return -1;
        }

        sessionLeaderPid = helperPid;
        sessionPid = response->sessionPid;
        xdgSessionId = response->xdgSessionId;

        if (xdgSessionId <= 0 || sessionPid <= 0) {
            qWarning() << "[Auth] Session helper failed to open session";
            close(lifecyclePipe[0]);
            return -1;
        }

        utmpLogin(true);
        m_notifier = new QSocketNotifier(lifecyclePipe[0], QSocketNotifier::Read);
        QObject::connect(m_notifier, &QSocketNotifier::activated, this, [this, lifecyclePipe] {
            close(lifecyclePipe[0]);
            m_notifier->setEnabled(false);
            m_notifier->deleteLater();
            Q_EMIT sessionFinished();
        });

        d->helperSession = true;
        sessionOpened = true;
        return xdgSessionId;
    }

    int runSessionHelper() {
        QByteArray requestData;
        if (!readAllFromFd(STDIN_FILENO, &requestData))
            return EXIT_FAILURE;

        auto request = deserializeRequest(requestData);
        if (!request.has_value())
            return EXIT_FAILURE;

        s_runningSessionHelper = true;
        if (const char *fd = getenv("DDM_SESSION_HELPER_LIFECYCLE_FD"))
            s_sessionHelperLifecycleFd = atoi(fd);

        Auth auth(nullptr, request->user);
        auth.type = static_cast<Display::DisplayServerType>(request->type);
        auth.tty = request->tty;
        auth.display = request->display;

        if (!auth.authenticate(request->secret))
            return EXIT_FAILURE;
        request->secret.fill('\0');

        QProcessEnvironment env;
        for (const QString &entry : request->environment) {
            const qsizetype separator = entry.indexOf(QLatin1Char('='));
            if (separator > 0)
                env.insert(entry.left(separator), entry.mid(separator + 1));
        }

        const int xdgSessionId = auth.openSession(request->command, env, request->cookie);
        if (xdgSessionId <= 0)
            return EXIT_FAILURE;

        const SessionHelperResponse response{ xdgSessionId, auth.sessionPid };
        if (!writeAllToFd(STDOUT_FILENO, serializeResponse(response)))
            return EXIT_FAILURE;
        close(STDOUT_FILENO);

        int status = 0;
        if (waitpid(auth.sessionLeaderPid, &status, 0) < 0)
            return EXIT_FAILURE;

        return WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;
    }

    int Auth::openSession(const QString &command,
                          QProcessEnvironment env,
                          const QByteArray &cookie) {
        Q_ASSERT(authenticated);

        if (type == Display::Treeland && !s_runningSessionHelper) {
            QByteArray secret = d->secret;
            d->secret.fill('\0');
            return openSessionInHelperProcess(command, env, cookie, secret);
        }

        int pipefd[2];
        if (pipe(pipefd) == -1) {
            qWarning() << "[Auth] pipe failed:" << strerror(errno);
            return -1;
        }

        // For Treeland sessions, switch VT after the session is registered in
        // Display::login(), otherwise the release signal cannot be processed
        // while this function is blocked waiting for the child process.
        if (type != Display::Treeland)
            VirtualTerminal::jumpToVt(tty, false, false);

        sessionLeaderPid = fork();
        switch (sessionLeaderPid) {
        case -1: {
            // Fork failed
            qWarning() << "[Auth] fork failed:" << strerror(errno);
            close(pipefd[0]);
            close(pipefd[1]);
            return -1;
        }
        case 0: {
            // Child (session leader) process
            close(pipefd[0]);
            if (s_runningSessionHelper) {
                close(STDOUT_FILENO);
                if (s_sessionHelperLifecycleFd >= 0)
                    close(s_sessionHelperLifecycleFd);
            }

            // Delete old signal handlers, in order to close old fds
            // which are shared with the parent process.
            if (daemonApp)
                delete daemonApp->signalHandler();

            // Restore default SIGINT and SIGTERM handlers. We need
            // the signal hander to terminate ourself, since we're
            // going to enter an infinite waiting loop and no one can
            // interrupt us after fork(), except the signal handler.
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);

            // Insert necessary environment
            struct passwd *pw = getpwnam(qPrintable(user));
            if (pw) {
                env.insert(QStringLiteral("HOME"), QString::fromLocal8Bit(pw->pw_dir));
                env.insert(QStringLiteral("PWD"), QString::fromLocal8Bit(pw->pw_dir));
                env.insert(QStringLiteral("SHELL"), QString::fromLocal8Bit(pw->pw_shell));
                env.insert(QStringLiteral("USER"), QString::fromLocal8Bit(pw->pw_name));
                env.insert(QStringLiteral("LOGNAME"), QString::fromLocal8Bit(pw->pw_name));
            }

            // Open session
            auto sessionEnv = openSessionInternal(env);
            if (!sessionEnv.has_value()) {
                qCritical() << "[SessionLeader] Failed to open session. Exit now.";
                exit(1);
            }
            env = *sessionEnv;

            // Retrieve XDG_SESSION_ID
            xdgSessionId = env.value(QStringLiteral("XDG_SESSION_ID")).toInt();
            if (xdgSessionId <= 0) {
                qCritical() << "[SessionLeader] Invalid XDG_SESSION_ID from pam_open_session()";
                exit(1);
            }
            if (write(pipefd[1], &xdgSessionId, sizeof(int)) != sizeof(int)) {
                qCritical() << "[SessionLeader] Failed to write XDG_SESSION_ID to parent process!";
                exit(1);
            }

            if (type == Display::Treeland) {
                UserSession session(this);
                session.setProcessEnvironment(env);
                sessionPid = session.startDirect(command, type, cookie);
                if (sessionPid <= 0) {
                    qCritical() << "[SessionLeader] Failed to start session process. Exit now.";
                    exit(1);
                }

                if (write(pipefd[1], &sessionPid, sizeof(qint64)) != sizeof(qint64)) {
                    qCritical() << "[SessionLeader] Failed to write session PID to parent process!";
                    exit(1);
                }
                qInfo() << "[SessionLeader] Session started with PID" << sessionPid;

                int status = 0;
                if (waitpid(static_cast<pid_t>(sessionPid), &status, 0) < 0) {
                    qCritical() << "[SessionLeader] Failed to wait session process:" << strerror(errno);
                    exit(1);
                }
                if (WIFSIGNALED(status)) {
                    qCritical() << "[SessionLeader] Session process crashed. Exit now.";
                    exit(1);
                }
                const int exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
                qInfo() << "[SessionLeader] Session process finished with exit code"
                        << exitCode << ". Exiting.";
                exit(exitCode);
            }

            // RUN!!!
            UserSession session(this);
            session.setProcessEnvironment(env);
            session.start(command, type, cookie);
            if (!session.waitForStarted()) {
                qCritical() << "[SessionLeader] Failed to start session process. Exit now.";
                exit(1);
            }

            // Send session PID to parent
            sessionPid = session.processId();
            if (write(pipefd[1], &sessionPid, sizeof(qint64)) != sizeof(qint64)) {
                qCritical() << "[SessionLeader] Failed to write session PID to parent process!";
                exit(1);
            }
            qInfo() << "[SessionLeader] Session started with PID" << sessionPid;

            session.waitForFinished(-1);

            // Handle session end
            if (session.exitStatus() == QProcess::CrashExit) {
                qCritical() << "[SessionLeader] Session process crashed. Exit now.";
                exit(1);
            }
            qInfo() << "[SessionLeader] Session process finished with exit code"
                    << session.exitCode() << ". Exiting.";
            exit(session.exitCode());
        }
        default: {
            // Parent process
            close(pipefd[1]);

            const ssize_t sessionIdBytes = read(pipefd[0], &xdgSessionId, sizeof(int));
            if (sessionIdBytes != sizeof(int)) {
                if (sessionIdBytes < 0)
                    qWarning() << "[Auth] Failed to read XDG_SESSION_ID from child process:" << strerror(errno);
                else
                    qWarning() << "[Auth] Failed to read complete XDG_SESSION_ID from child process:" << sessionIdBytes;
                close(pipefd[0]);
                return -1;
            }
            const ssize_t sessionPidBytes = read(pipefd[0], &sessionPid, sizeof(qint64));
            if (sessionPidBytes != sizeof(qint64)) {
                if (sessionPidBytes < 0)
                    qWarning() << "[Auth] Failed to read session PID from child process:" << strerror(errno);
                else
                    qWarning() << "[Auth] Failed to read complete session PID from child process:" << sessionPidBytes;
                close(pipefd[0]);
                return -1;
            }
            utmpLogin(true);

            // Monitor child process ends
            m_notifier = new QSocketNotifier(pipefd[0], QSocketNotifier::Read);
            connect(m_notifier, &QSocketNotifier::activated, this, [this, pipefd] {
                close(pipefd[0]);
                m_notifier->setEnabled(false);
                m_notifier->deleteLater();
                Q_EMIT sessionFinished();
            });

            sessionOpened = true;
            return xdgSessionId;
        }
        }
    }

#define CHECK_RET_CLOSE                                                          \
    if (d->ret != PAM_SUCCESS) {                                                 \
        qWarning() << "[Auth] closeSession:" << pam_strerror(d->handle, d->ret); \
        return false;                                                            \
    }
    bool Auth::closeSession() {
        if (!sessionOpened) {
            qWarning() << "[Auth] closeSession: Session was not opened.";
            return true;
        }
        qWarning() << "[Auth] Closing session for user" << user;

        d->ret = pam_close_session(d->handle, 0);
        CHECK_RET_CLOSE

        sessionOpened = false;
        d->ret = pam_setcred(d->handle, PAM_DELETE_CRED);
        CHECK_RET_CLOSE

        qInfo() << "[Auth] Session closed.";
        return true;
    }

#define CHECK_RET_OPEN                                                                  \
    if (d->ret != PAM_SUCCESS) {                                                        \
        qWarning() << "[Auth] openSessionInternal:" << pam_strerror(d->handle, d->ret); \
        return std::nullopt;                                                            \
    }
    std::optional<QProcessEnvironment> Auth::openSessionInternal(const QProcessEnvironment &sessionEnv) {
        qInfo() << "[Auth] Opening session for user" << user;

        d->ret = pam_setcred(d->handle, PAM_ESTABLISH_CRED);
        CHECK_RET_OPEN

        // Set PAM_TTY
        QString vtPath = VirtualTerminal::path(tty);
        d->ret = pam_set_item(d->handle, PAM_TTY, qPrintable(vtPath));
        CHECK_RET_OPEN

        // Set PAM_XDISPLAY
        if (!display.isEmpty()) {
            d->ret = pam_set_item(d->handle, PAM_XDISPLAY, qPrintable(display));
            CHECK_RET_OPEN
        }

        // Insert environments into new session
        QStringList envStrs = sessionEnv.toStringList();
        for (const QString &s : std::as_const(envStrs)) {
            d->ret = pam_putenv(d->handle, qPrintable(s));
            CHECK_RET_OPEN
        }

        // OPEN!!!
        d->ret = pam_open_session(d->handle, 0);
        CHECK_RET_OPEN

        qInfo() << "[Auth] Session opened.";

        // Retrieve env vars in new session
        QProcessEnvironment env;
        char **envlist = pam_getenvlist(d->handle);
        if (envlist) {
            for (int i = 0; envlist[i] != nullptr; ++i) {
                QString str = QString::fromLocal8Bit(envlist[i]);
                int equalPos = str.indexOf('=');
                if (equalPos != -1)
                    env.insert(str.left(equalPos), str.mid(equalPos + 1));
                free(envlist[i]);
            }
            free(envlist);
        }
        return env;
    }
} // namespace DDM

#include "Auth.moc"
