import { z } from 'zod';

import { REST_API } from '../../api';

export namespace SyncIpLimitsCommand {
    export const url = REST_API.HANDLER.SYNC_IP_LIMITS;

    // The whole table: users left out lose their limit on this node.
    export const RequestSchema = z.object({
        users: z.array(
            z.object({
                username: z.string(),
                limit: z.int().min(1),
                // IPs the panel saw this user on, across all nodes, that keep their slots.
                ips: z.array(z.string()),
            }),
        ),
    });

    export type Request = z.infer<typeof RequestSchema>;

    export const ResponseSchema = z.object({
        response: z.object({
            success: z.boolean(),
        }),
    });

    export type Response = z.infer<typeof ResponseSchema>;
}
