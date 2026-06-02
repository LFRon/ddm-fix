// Copyright (C) 2025-2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <QObject>
#include <QScopedPointer>

class QLocalSocket;
class QRemoteObjectNode;
class TreelandDDMRemoteReplica;

namespace DDM {
class TreelandConnector : public QObject {
    Q_OBJECT
public:
    explicit TreelandConnector(QObject *parent = nullptr);
    ~TreelandConnector();
    bool isConnected();
    int mainPid();
    void connect(const QString &socketPath);
    void disconnect();

    void switchToGreeter();
    void switchToUser(const QString &username);
private:
    bool ensureRemote();
    int treelandMainPid() const;

    QScopedPointer<QLocalSocket> m_remoteSocket;
    QScopedPointer<QRemoteObjectNode> m_remoteNode;
    QScopedPointer<TreelandDDMRemoteReplica> m_remoteReplica;
};
}
