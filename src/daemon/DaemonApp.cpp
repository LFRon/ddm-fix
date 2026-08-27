/***************************************************************************
 * Copyright (C) 2025-2026 UnionTech Software Technology Co., Ltd.
 * Copyright (c) 2013 Abdurrahman AVCI <abdurrahmanavci@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 ***************************************************************************/

#include "DaemonApp.h"

#include "Configuration.h"
#include "Constants.h"
#include "DdeSeatdControl.h"
#include "DisplayManager.h"
#include "PowerManager.h"
#include "SeatManager.h"
#include "SignalHandler.h"
#include "TreelandConnector.h"

#include "MessageHandler.h"

#include <QDBusConnectionInterface>
#include <QDBusInterface>
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QHostInfo>
#include <QProcess>
#include <QStandardPaths>
#include <QTimer>

#include <iostream>

namespace DDM {
    DaemonApp *DaemonApp::self = nullptr;

    static void applyXwaylandIpcCapability()
    {
        const QStringList candidates = [&]() -> QStringList {
            QStringList list;
            const QString found = QStandardPaths::findExecutable(QStringLiteral("Xwayland"));
            if (!found.isEmpty())
                list << found;
            list << QStringLiteral("/usr/bin/Xwayland");
            return list;
        }();

        const QString setcapBin = []() -> QString {
            QString bin = QStandardPaths::findExecutable(QStringLiteral("setcap"));
            if (bin.isEmpty() && QFile::exists(QStringLiteral("/usr/sbin/setcap")))
                bin = QStringLiteral("/usr/sbin/setcap");
            return bin;
        }();
        if (setcapBin.isEmpty()) {
            qWarning() << "setcap not found, cannot grant cap_ipc_owner to Xwayland";
            return;
        }

        for (const QString &path : std::as_const(candidates)) {
            if (!QFile::exists(path) || !QFileInfo(path).isExecutable())
                continue;
            const int ret = QProcess::execute(setcapBin,
                                              { QStringLiteral("cap_ipc_owner=ep"), path });
            if (ret == 0)
                qInfo() << "Granted cap_ipc_owner to" << path;
            else
                qWarning() << "setcap on" << path << "failed (exit" << ret << ")";
            break;
        }
    }

    DaemonApp::DaemonApp(int &argc, char **argv) : QCoreApplication(argc, argv) {
        // point instance to this
        self = this;

        qInstallMessageHandler(DDM::DaemonMessageHandler);

        // log message
        qDebug() << "Initializing...";

        bool consoleKitServiceActivatable = false;
        QDBusReply<QStringList> activatableNamesReply = QDBusConnection::systemBus().interface()->activatableServiceNames();
        if (activatableNamesReply.isValid()) {
            consoleKitServiceActivatable = activatableNamesReply.value().contains(QStringLiteral("org.freedesktop.ConsoleKit"));
        }

        // If ConsoleKit isn't started by the OS init system (FreeBSD, for instance),
        // we start it ourselves during the ddm startup
        if (consoleKitServiceActivatable) {
            QDBusReply<bool> registeredReply = QDBusConnection::systemBus().interface()->isServiceRegistered(QStringLiteral("org.freedesktop.ConsoleKit"));
            if (registeredReply.isValid() && registeredReply.value() == false) {
                QDBusConnection::systemBus().interface()->startService(QStringLiteral("org.freedesktop.ConsoleKit"));
            }
        }

        // create display manager
        m_displayManager = new DisplayManager(this);

        // create power manager
        m_powerManager = new PowerManager(this);

        // create seat manager
        m_seatManager = new SeatManager(this);

        // connect with display manager
        connect(m_seatManager, &SeatManager::seatCreated, m_displayManager, &DisplayManager::AddSeat);
        connect(m_seatManager, &SeatManager::seatRemoved, m_displayManager, &DisplayManager::RemoveSeat);

        // create signal handler
        m_signalHandler = new SignalHandler(this);

        // quit when SIGINT, SIGTERM received
        connect(m_signalHandler, &SignalHandler::sigintReceived, this, &DaemonApp::quit);
        connect(m_signalHandler, &SignalHandler::sigtermReceived, this, &DaemonApp::quit);

        m_seatdControl = new DdeSeatdControl(this);
        m_treelandConnector = new TreelandConnector(this);
        connect(m_seatdControl, &DdeSeatdControl::vtChanged,
                m_seatManager, &SeatManager::handleVtChanged);
        if (!m_seatdControl->connectEventSocket())
            qWarning() << "Failed to connect dde-seatd event socket during startup";
        // log message
        qDebug() << "Starting...";

        // Xwayland runs as the display manager's user (e.g. "dde") while
        // desktop X11 clients may be launched by the real login user.
        // MIT-SHM (XShmPutImage) fails with BadAccess when the SysV shared
        // memory segment UID differs from the X server UID ── shmat() is
        // denied by the kernel.  Grant cap_ipc_owner to the Xwayland binary
        // so it can attach segments created by any user on the machine.
        // The X server still enforces its own per-client access check
        // (Xext/shm.c:shm_access, which verifies the client owns the seg).
        // See also: debian/ddm.postinst (install-time) and postrm (cleanup).
        applyXwaylandIpcCapability();

        m_seatManager->initialize();
    }

    QString DaemonApp::hostName() const {
        return QHostInfo::localHostName();
    }

    int DaemonApp::newSessionId() {
        return m_lastSessionId++;
    }

    void DaemonApp::backToNormal() {
        QDBusInterface interface("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", QDBusConnection::systemBus());
        qDebug() << interface.call("ReenableUnitFiles", QStringList() << "lightdm.service", false, true);
    }
}

int main(int argc, char **argv) {
    QStringList arguments;

    for (int i = 0; i < argc; i++)
        arguments << QString::fromLocal8Bit(argv[i]);

    if (arguments.contains(QStringLiteral("--help")) || arguments.contains(QStringLiteral("-h"))) {
        std::cout << "Usage: ddm [options]\n"
                  << "Options: \n"
                  << "  --example-config    Print the complete current configuration to stdout" << std::endl;

        return EXIT_FAILURE;
    }

    // spit a complete config file on stdout and quit on demand
    if (arguments.contains(QStringLiteral("--example-config"))) {
        DDM::mainConfig.wipe();
        QTextStream(stdout) << DDM::mainConfig.toConfigFull();
        return EXIT_SUCCESS;
    }

    // create application
    DDM::DaemonApp app(argc, argv);

    // run application
    return app.exec();
}
