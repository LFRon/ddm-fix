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

#ifndef DDM_AUTH_SESSION_H
#define DDM_AUTH_SESSION_H

#include <QtCore/QObject>
#include <QtCore/QProcess>
#include <QtCore/QTemporaryFile>

#include "Display.h"

namespace DDM {
    class UserSession : public QProcess {
        Q_OBJECT
    public:
        explicit UserSession(Auth *parent);

        void start(const QString &command,
                   Display::DisplayServerType type,
                   const QByteArray &cookie = QByteArray());
        qint64 startDirect(const QString &command,
                           Display::DisplayServerType type,
                           const QByteArray &cookie = QByteArray());
        void stop();

    private:
        // Don't call it directly, it will be invoked by the child process only
        void childModifier();
        void prepareChildContext(Display::DisplayServerType type);

        QTemporaryFile m_xauthFile;
        Display::DisplayServerType m_sessionType = Display::Wayland;
        QByteArray m_userName;
        QByteArray m_ttyPath;
        QList<QByteArray> m_namespaces;
        QByteArray m_sessionLogFile;
        int m_xauthFd = -1;
    };
}

#endif // DDM_AUTH_SESSION_H
