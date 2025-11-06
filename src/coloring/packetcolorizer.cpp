#include "packetcolorizer.h"

#include <QDebug>
#include <QFile>
#include <QIODevice>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSettings>

PacketColorizer::PacketColorizer()
    : m_dummyHandle(pcap_open_dead(DLT_EN10MB, 65535))
    , m_dummyNetmask(0)
    , m_linkType(DLT_EN10MB)
{}

PacketColorizer::~PacketColorizer() {
    clearRules();
    if (m_dummyHandle) {
        pcap_close(m_dummyHandle);
    }
}

void PacketColorizer::addRule(ColoringRule&& rule) {
    if (!m_dummyHandle) {
        qWarning() << "Cannot add coloring rule without a dummy handle";
        return;
    }
    if (!rule.compile(m_dummyHandle, m_dummyNetmask)) {
        qWarning() << "Failed to compile coloring rule" << rule.bpfExpression;
        return;
    }
    m_rules.append(std::move(rule));
}

void PacketColorizer::clearRules() {
    for (auto &rule : m_rules) {
        pcap_freecode(&rule.prog);
    }
    m_rules.clear();
}

QColor PacketColorizer::colorFor(const pcap_pkthdr* hdr,
                                 const u_char* pkt) const
{
    for (const auto &r : m_rules) {
        if (r.matches(hdr, pkt))
            return r.color;
    }
    return QColor();
}

void PacketColorizer::setLinkType(int linkType, bpf_u_int32 netmask) {
    if (linkType == m_linkType && netmask == m_dummyNetmask) {
        return;
    }

    if (m_dummyHandle) {
        pcap_close(m_dummyHandle);
        m_dummyHandle = nullptr;
    }

    m_dummyHandle = pcap_open_dead(linkType, 65535);
    if (!m_dummyHandle) {
        qWarning() << "Failed to create dummy handle for link type" << linkType;
        return;
    }

    m_linkType = linkType;
    m_dummyNetmask = netmask;
    recompileRules();
}

void PacketColorizer::recompileRules() {
    if (!m_dummyHandle) {
        return;
    }

    for (auto &rule : m_rules) {
        pcap_freecode(&rule.prog);
        if (!rule.compile(m_dummyHandle, m_dummyNetmask)) {
            qWarning() << "Failed to compile coloring rule" << rule.bpfExpression
                       << "for link type" << m_linkType;
        }
    }
}

// ----------------------------------------------------------------
// Settings (.config)
// ----------------------------------------------------------------

void PacketColorizer::saveRulesToSettings() {
    if (m_rules.isEmpty()) return;
    QSettings s("Engineering", "FoxProbe");
    s.beginGroup("ColoringRules");
    s.remove("");
    for (int i = 0; i < m_rules.size(); ++i) {
        s.beginGroup(QString::number(i));
        s.setValue("bpf",   m_rules[i].bpfExpression);
        s.setValue("color", m_rules[i].color.name());
        s.endGroup();
    }
    s.endGroup();
}

void PacketColorizer::loadRulesFromSettings() {
    QSettings s("Engineering", "FoxProbe");
    s.beginGroup("ColoringRules");
    QStringList groups = s.childGroups();
    for (auto &grp : groups) {
        s.beginGroup(grp);
        QString bpf = s.value("bpf").toString();
        QString col = s.value("color").toString();
        s.endGroup();
        if (bpf.isEmpty())   continue;
        QColor  c(col);
        if (!c.isValid())    continue;
        ColoringRule rule;
        rule.bpfExpression = bpf;
        rule.color         = c;
        addRule(std::move(rule));
    }
    s.endGroup();
}

// ----------------------------------------------------------------
// JSON export/import
// ----------------------------------------------------------------

bool PacketColorizer::saveRulesToJson(const QString &filePath) {
    QJsonArray arr;
    for (auto &r : m_rules) {
        QJsonObject o;
        o["bpf"]   = r.bpfExpression;
        o["color"] = r.color.name();
        arr.append(o);
    }
    QJsonDocument doc(arr);

    QFile f(filePath);
    if (!f.open(QIODevice::WriteOnly)) return false;
    f.write(doc.toJson());
    return true;
}

bool PacketColorizer::loadRulesFromJson(const QString &filePath) {
    QFile f(filePath);
    if (!f.open(QIODevice::ReadOnly)) return false;
    auto doc = QJsonDocument::fromJson(f.readAll());
    if (!doc.isArray()) return false;

    clearRules();
    for (auto val : doc.array()) {
        auto o = val.toObject();
        QString bpf = o["bpf"].toString();
        QString col = o["color"].toString();
        QColor  c(col);
        if (bpf.isEmpty() || !c.isValid()) continue;
        ColoringRule rule;
        rule.bpfExpression = bpf;
        rule.color         = c;
        addRule(std::move(rule));
    }
    return true;
}
