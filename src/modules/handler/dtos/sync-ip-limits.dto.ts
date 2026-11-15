import { createZodDto } from 'nestjs-zod';

import { SyncIpLimitsCommand } from '@libs/contracts/commands/handler';

export class SyncIpLimitsRequestDto extends createZodDto(SyncIpLimitsCommand.RequestSchema) {}
export class SyncIpLimitsResponseDto extends createZodDto(SyncIpLimitsCommand.ResponseSchema) {}
