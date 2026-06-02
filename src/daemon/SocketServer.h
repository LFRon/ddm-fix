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

#ifndef DDM_SOCKETSERVER_H
#define DDM_SOCKETSERVER_H

#include "rep_ddmremote_source.h"

#include <QObject>
#include <QString>

#include "Session.h"

class QLocalServer;
class QLocalSocket;
class QRemoteObjectHost;

namespace DDM {
    class Display;
    class PowerManager;

    class SocketServer : public DDMRemoteSimpleSource {
        Q_OBJECT
        Q_DISABLE_COPY(SocketServer)
    public:
        explicit SocketServer(Display *display, QObject *parent = 0);

        bool start();
        void stop();

        QString socketAddress() const;

        void replayUserSessions();
        void addUserSession(const QString &user, int sessionId);
        void removeUserSession(const QString &user, int sessionId);

    private slots:
        void newConnection();

    public slots:
        bool connectGreeter() override;
        bool login(QString user, QString password, int sessionType, QString sessionFile) override;
        bool logout(int id) override;
        bool powerOff() override;
        bool reboot() override;
        bool suspend() override;
        bool hibernate() override;
        bool hybridSleep() override;

    private:
        QLocalServer *m_server { nullptr };
        QRemoteObjectHost *m_host { nullptr };
        Display *m_display { nullptr };
        PowerManager *m_powerManager { nullptr };
    };
}

#endif // DDM_SOCKETSERVER_H
