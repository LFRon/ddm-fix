/***************************************************************************
* Copyright (c) 2015 Pier Luigi Fiorini <pierluigi.fiorini@gmail.com>
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

#include "SocketServer.h"

#include "DaemonApp.h"
#include "PowerManager.h"
#include "TreelandConnector.h"
#include "Utils.h"

#include <QLocalServer>
#include <QLocalSocket>
#include <QRemoteObjectHost>

namespace DDM {
    SocketServer::SocketServer(QObject *parent)
        : GreeterDDMRemoteSimpleSource(parent) {
    }

    QString SocketServer::socketAddress() const {
        if (m_server)
            return m_server->fullServerName();
        return QString();
    }

    bool SocketServer::start(const QString &displayName) {
        // check if the server has been created already
        if (m_server)
            return false;

        QString socketName = QStringLiteral("ddm-%1-%2").arg(displayName).arg(generateName(6));

        // log message
        qDebug() << "Socket server starting...";

        m_server = new QLocalServer(this);
        m_server->setSocketOptions(QLocalServer::UserAccessOption);
        if (!m_server->listen(socketName)) {
            qCritical() << "Failed to start socket server.";
            delete m_server;
            m_server = nullptr;
            return false;
        }

        m_host = new QRemoteObjectHost(this);
        if (!m_host->enableRemoting(this, QStringLiteral("GreeterDDMRemote"))) {
            qCritical() << "Failed to enable GreeterDDMRemote source.";
            m_server->close();
            delete m_server;
            m_server = nullptr;
            delete m_host;
            m_host = nullptr;
            return false;
        }

        setHostName(daemonApp->hostName());
        const auto capabilities = daemonApp->powerManager()->capabilities();
        setCanPowerOff(capabilities & Capability::PowerOff);
        setCanReboot(capabilities & Capability::Reboot);
        setCanSuspend(capabilities & Capability::Suspend);
        setCanHibernate(capabilities & Capability::Hibernate);
        setCanHybridSleep(capabilities & Capability::HybridSleep);

        qDebug() << "Socket server started.";
        connect(m_server, &QLocalServer::newConnection, this, &SocketServer::newConnection);
        return true;
    }

    void SocketServer::stop() {
        if (!m_server)
            return;

        qDebug() << "Socket server stopping...";
        if (m_host) {
            m_host->deleteLater();
            m_host = nullptr;
        }
        m_server->close();
        m_server->deleteLater();
        m_server = nullptr;
        qDebug() << "Socket server stopped.";
    }

    void SocketServer::newConnection() {
        while (m_server && m_server->hasPendingConnections()) {
            auto *socket = m_server->nextPendingConnection();
            if (!socket)
                continue;

            connect(socket, &QLocalSocket::disconnected, socket, &QLocalSocket::deleteLater);
            connect(socket, &QLocalSocket::disconnected, this, [this] {
                Q_EMIT disconnected();
            });
            m_host->addHostSideConnection(socket);
        }
    }

    void SocketServer::connectGreeter() {
        qDebug() << "Message received from greeter: Connect";
        daemonApp->treelandConnector()->connect({});
        setHostName(daemonApp->hostName());
        const auto capabilities = daemonApp->powerManager()->capabilities();
        setCanPowerOff(capabilities & Capability::PowerOff);
        setCanReboot(capabilities & Capability::Reboot);
        setCanSuspend(capabilities & Capability::Suspend);
        setCanHibernate(capabilities & Capability::Hibernate);
        setCanHybridSleep(capabilities & Capability::HybridSleep);
        Q_EMIT connected();
    }

    void SocketServer::login(QString user, QString password, int sessionType, QString sessionFile) {
        qDebug() << "Message received from greeter: Login";
        Session session(static_cast<Session::Type>(sessionType), sessionFile);
        Q_EMIT loginRequested(user, password, session);
    }

    void SocketServer::logout(int id) {
        qDebug() << "Message received from greeter: Logout";
        Q_EMIT logoutRequested(id);
    }

    void SocketServer::lock(int id) {
        qDebug() << "Message received from greeter: Lock";
        Q_EMIT lockRequested(id);
    }

    void SocketServer::unlock(QString user, QString password) {
        qDebug() << "Message received from greeter: Unlock";
        Q_EMIT unlockRequested(user, password);
    }

    void SocketServer::powerOff() {
        qDebug() << "Message received from greeter: PowerOff";
        daemonApp->powerManager()->powerOff();
    }

    void SocketServer::reboot() {
        qDebug() << "Message received from greeter: Reboot";
        daemonApp->powerManager()->reboot();
    }

    void SocketServer::suspend() {
        qDebug() << "Message received from greeter: Suspend";
        daemonApp->powerManager()->suspend();
    }

    void SocketServer::hibernate() {
        qDebug() << "Message received from greeter: Hibernate";
        daemonApp->powerManager()->hibernate();
    }

    void SocketServer::hybridSleep() {
        qDebug() << "Message received from greeter: HybridSleep";
        daemonApp->powerManager()->hybridSleep();
    }
}
