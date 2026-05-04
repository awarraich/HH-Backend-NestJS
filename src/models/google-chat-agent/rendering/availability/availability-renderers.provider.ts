import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { CardRendererRegistry } from '../renderer.registry';
import { myAvailabilityCardRenderer } from './my-availability.card';
import { timeOffListCardRenderer } from './time-off-list.card';
import {
  cancelTimeOffCardRenderer,
  requestTimeOffCardRenderer,
  setAvailabilityCardRenderer,
} from './write-confirmation.cards';

/**
 * Registers M6 (read) + M7 (write) availability card renderers with
 * the agent's renderer registry on module init. Mirrors the pattern
 * established by ShiftRenderersProvider.
 */
@Injectable()
export class AvailabilityRenderersProvider implements OnModuleInit {
  private readonly logger = new Logger(AvailabilityRenderersProvider.name);

  constructor(private readonly renderers: CardRendererRegistry) {}

  onModuleInit(): void {
    this.renderers.register(myAvailabilityCardRenderer);
    this.renderers.register(timeOffListCardRenderer);
    this.renderers.register(setAvailabilityCardRenderer);
    this.renderers.register(requestTimeOffCardRenderer);
    this.renderers.register(cancelTimeOffCardRenderer);
    this.logger.log('Registered M6+M7 availability card renderers (5)');
  }
}
