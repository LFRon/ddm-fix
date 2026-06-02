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

#include "rep_greeterddmremote_source.h"

#include <QObject>
#include <QString>

#include "Session.h"

class QLocalServer;
class QLocalSocket;
class QRemoteObjectHost;

namespace DDM {
    class SocketServer : public GreeterDDMRemoteSimpleSource {
        Q_OBJECT
        Q_DISABLE_COPY(SocketServer)
    public:
        explicit SocketServer(QObject *parent = 0);

        bool start(const QString &sddmName);
        void stop();

        QString socketAddress() const;

    private slots:
        void newConnection();

    public slots:
        void connectGreeter() override;
        void login(QString user, QString password, int sessionType, QString sessionFile) override;
        void logout(int id) override;
        void lock(int id) override;
        void unlock(QString user, QString password) override;
        void powerOff() override;
        void reboot() override;
        void suspend() override;
        void hibernate() override;
        void hybridSleep() override;

    signals:
        void loginRequested(const QString &user, const QString &password, const Session &session);
        void logoutRequested(int id);
        void lockRequested(int id);
        void unlockRequested(const QString &user, const QString &password);
        void connected();
        void disconnected();

    private:
        QLocalServer *m_server { nullptr };
        QRemoteObjectHost *m_host { nullptr };
    };
}

#endif // DDM_SOCKETSERVER_H
