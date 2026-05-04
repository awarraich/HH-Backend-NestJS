import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { CardRendererRegistry } from '../renderer.registry';
import { myShiftsCardRenderer } from './my-shifts.card';
import { shiftDetailCardRenderer } from './shift-detail.card';
import { availableShiftsCardRenderer } from './available-shifts.card';

/**
 * Registers M5's shift card renderers with the renderer registry on
 * module init. Mirrors the ShiftToolsProvider pattern from M5.
 */
@Injectable()
export class ShiftRenderersProvider implements OnModuleInit {
  private readonly logger = new Logger(ShiftRenderersProvider.name);

  constructor(private readonly renderers: CardRendererRegistry) {}

  onModuleInit(): void {
    this.renderers.register(myShiftsCardRenderer);
    this.renderers.register(shiftDetailCardRenderer);
    this.renderers.register(availableShiftsCardRenderer);
    this.logger.log('Registered M9 shift card renderers (3)');
  }
}
