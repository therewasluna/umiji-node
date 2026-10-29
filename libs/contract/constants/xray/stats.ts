export const XRAY_DEFAULT_POLICY_MODEL = {
    policy: {
        levels: {
            '0': {
                statsUserUplink: true,
                statsUserDownlink: true,
                statsUserOnline: true,
            },
        },
        system: {
            statsInboundDownlink: true,
            statsInboundUplink: true,
            statsOutboundDownlink: true,
            statsOutboundUplink: true,
        },
    },
} as const;

export const XRAY_DEFAULT_STATS_MODEL = {
    stats: {},
} as const;

export const XRAY_DEFAULT_API_MODEL = {
    api: {
        services: ['HandlerService', 'StatsService', 'RoutingService'],
        tag: 'UMIJI_API',
    },
} as const;

export const XRAY_API_INBOUND_MODEL = ({ xtlsApiSocketPath }: { xtlsApiSocketPath: string }) =>
    ({
        tag: 'UMIJI_API_INBOUND',
        listen: `@${xtlsApiSocketPath}`,
        protocol: 'tunnel',
    }) as const;

export const XRAY_ROUTING_RULES_MODEL = {
    inboundTag: ['UMIJI_API_INBOUND'],
    outboundTag: 'UMIJI_API',
} as const;

export const XRAY_TORRENT_BLOCKER_ROUTING_RULES_MODEL = ({
    webhookUrl,
}: {
    webhookUrl: string;
}) => ({
    protocol: ['bittorrent'],
    outboundTag: 'UMIJI_TB_OUTBOUND_BLOCK',
    webhook: {
        url: webhookUrl,
        deduplication: 5,
    },
});

export const XRAY_TORRENT_BLOCKER_OUTBOUND_MODEL = {
    tag: 'UMIJI_TB_OUTBOUND_BLOCK',
    protocol: 'blackhole',
} as const;

export const XRAY_TORRENT_BLOCKER_OUTBOUND_TAG = 'UMIJI_TB_OUTBOUND_BLOCK';
