import { Logger, Module, OnApplicationShutdown } from '@nestjs/common';

import { PluginModule } from './_plugin/plugin.module';
import { AsnLmdbModule } from './asn-lmdb/asn-lmdb.module';
import { HandlerModule } from './handler/handler.module';
import { NetworkStatsModule } from './network-stats/network-stats.module';
import { StatsModule } from './stats/stats.module';
import { XrayModule } from './xray-core/xray.module';

@Module({
    imports: [
        AsnLmdbModule,
        NetworkStatsModule,
        PluginModule,
        StatsModule,
        XrayModule,
        HandlerModule,
    ],
    providers: [],
})
export class UmijiNodeModules implements OnApplicationShutdown {
    private readonly logger = new Logger(UmijiNodeModules.name);

    async onApplicationShutdown(signal?: string): Promise<void> {
        this.logger.log(`${signal} received, shutting down...`);
    }
}
