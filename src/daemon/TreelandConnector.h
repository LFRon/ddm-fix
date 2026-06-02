// Copyright (C) 2025-2026 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: GPL-2.0-or-later

#include <QObject>
#include <QLocalSocket>
#include <QByteArray>
#include <QScopedPointer>

class QRemoteObjectNode;
class TreelandDDMRemoteReplica;

namespace DDM {
class TreelandConnector : public QObject {
    Q_OBJECT
public:
    TreelandConnector();
    ~TreelandConnector();
    bool isConnected();
    void setSignalHandler();
    void connect(const QString socketPath);
    void disconnect();
    int createGroupVtForTreeland(const QString &user, const QString &sessionId);
    void destroyGroupVt(int vt);

    void switchToGreeter();
    void switchToUser(const QString username);
private:
    bool ensureRemote();
    bool connectControlSocket();
    void disconnectControlSocket();
    void handleControlSocket();
    int treelandMainPid() const;
    bool sendDestroyGroupVt(int vt);

    QLocalSocket *m_controlSocket { nullptr };
    QScopedPointer<QLocalSocket> m_remoteSocket;
    QScopedPointer<QRemoteObjectNode> m_remoteNode;
    QScopedPointer<TreelandDDMRemoteReplica> m_remoteReplica;
    QByteArray m_controlBuffer;
};
}
