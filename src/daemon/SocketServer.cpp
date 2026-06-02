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

#include "Auth.h"
#include "DaemonApp.h"
#include "Display.h"
#include "PowerManager.h"
#include "TreelandConnector.h"

#include <QAbstractSocket>
#include <QLocalServer>
#include <QLocalSocket>
#include <QRemoteObjectHost>

static constexpr auto ddmRemoteSocketName = "org.deepin.dde.ddm.qro";
static constexpr auto ddmRemoteSourceName = "DDMRemote";

namespace DDM {
    SocketServer::SocketServer(Display *display, QObject *parent)
        : DDMRemoteSimpleSource(parent)
        , m_display(display)
        , m_powerManager(daemonApp->powerManager()) {
    }

    QString SocketServer::socketAddress() const {
        if (m_server)
            return m_server->fullServerName();
        return QString();
    }

    bool SocketServer::start() {
        // check if the server has been created already
        if (m_server)
            return false;

        // log message
        qDebug() << "Socket server starting...";

        m_server = new QLocalServer(this);
        m_server->setSocketOptions(QLocalServer::UserAccessOption);
        if (!m_server->listen(QString::fromLatin1(ddmRemoteSocketName))) {
            if (m_server->serverError() != QAbstractSocket::AddressInUseError
                    || !QLocalServer::removeServer(QString::fromLatin1(ddmRemoteSocketName))
                    || !m_server->listen(QString::fromLatin1(ddmRemoteSocketName))) {
                qCritical() << "Failed to start socket server.";
                delete m_server;
                m_server = nullptr;
                return false;
            }
        }

        m_host = new QRemoteObjectHost(this);
        if (!m_host->enableRemoting(this, QString::fromLatin1(ddmRemoteSourceName))) {
            qCritical() << "Failed to enable DDMRemote source.";
            m_server->close();
            delete m_server;
            m_server = nullptr;
            delete m_host;
            m_host = nullptr;
            return false;
        }

        setHostName(daemonApp->hostName());
        const auto capabilities = m_powerManager->capabilities();
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
            m_host->addHostSideConnection(socket);
        }
    }

    bool SocketServer::connectGreeter() {
        qDebug() << "Message received from greeter: Connect";
        daemonApp->treelandConnector()->connect();
        m_display->connected();
        return true;
    }

    void SocketServer::replayUserSessions() {
        for (Auth *auth : std::as_const(m_display->auths)) {
            if (auth->sessionOpened)
                addUserSession(auth->user, auth->xdgSessionId);
        }
    }

    void SocketServer::addUserSession(const QString &user, int sessionId) {
        if (sessionId > 0)
            emit userSessionAdded(user, sessionId);
    }

    void SocketServer::removeUserSession(const QString &user, int sessionId) {
        if (sessionId > 0)
            emit userSessionRemoved(user, sessionId);
    }

    bool SocketServer::login(QString user, QString password, int sessionType, QString sessionFile) {
        qDebug() << "Message received from greeter: Login";
        Session session(static_cast<Session::Type>(sessionType), sessionFile);
        m_display->login(user, password, session);
        return true;
    }

    bool SocketServer::logout(int id) {
        qDebug() << "Message received from greeter: Logout";
        m_display->logout(id);
        return true;
    }

    bool SocketServer::powerOff() {
        qDebug() << "Message received from greeter: PowerOff";
        m_powerManager->powerOff();
        return true;
    }

    bool SocketServer::reboot() {
        qDebug() << "Message received from greeter: Reboot";
        m_powerManager->reboot();
        return true;
    }

    bool SocketServer::suspend() {
        qDebug() << "Message received from greeter: Suspend";
        m_powerManager->suspend();
        return true;
    }

    bool SocketServer::hibernate() {
        qDebug() << "Message received from greeter: Hibernate";
        m_powerManager->hibernate();
        return true;
    }

    bool SocketServer::hybridSleep() {
        qDebug() << "Message received from greeter: HybridSleep";
        m_powerManager->hybridSleep();
        return true;
    }
}
