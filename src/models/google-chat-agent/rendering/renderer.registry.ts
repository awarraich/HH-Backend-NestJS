import { Injectable, Logger } from '@nestjs/common';
import { CardV2Message } from './card.types';

/**
 * A renderer turns a tool's output into a Card v2 message. Each tool name
 * maps to at most one renderer. Tools without a renderer fall back to plain
 * text in the agent loop (the model's prose is sent as-is).
 *
 * Renderers receive the model's accompanying summary text so they can use
 * it as a card header, falling back to a default if absent.
 */
export interface CardRenderer<T = unknown> {
  /** Tool name this renderer handles (matches `Tool.name`). */
  toolName: string;
  /** Build a card from the tool output. Return null to fall back to text. */
  render(output: T, summary: string): CardV2Message | null;
}

@Injectable()
export class CardRendererRegistry {
  private readonly logger = new Logger(CardRendererRegistry.name);
  private readonly byTool = new Map<string, CardRenderer>();

  register(renderer: CardRenderer): void {
    if (this.byTool.has(renderer.toolName)) {
      throw new Error(
        `A card renderer for tool "${renderer.toolName}" is already registered.`,
      );
    }
    this.byTool.set(renderer.toolName, renderer as CardRenderer);
    this.logger.log(`Registered card renderer for tool: ${renderer.toolName}`);
  }

  has(toolName: string): boolean {
    return this.byTool.has(toolName);
  }

  /**
   * Render the output of a tool call. Returns null when:
   *   - no renderer is registered for the tool, or
   *   - the renderer itself returned null (signaling text-fallback).
   */
  render(
    toolName: string,
    output: unknown,
    summary: string,
  ): CardV2Message | null {
    const renderer = this.byTool.get(toolName);
    if (!renderer) return null;
    return renderer.render(output, summary);
  }

  size(): number {
    return this.byTool.size;
  }

  list(): string[] {
    return Array.from(this.byTool.keys());
  }
}
