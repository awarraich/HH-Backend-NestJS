/**
 * Minimal subset of Google Chat Card v2 we actually use. Defined locally
 * rather than importing the full @googleapis/chat surface so the renderer
 * code stays focused and the test fixtures stay legible.
 *
 * Reference: https://developers.google.com/chat/api/guides/v1/messages/create#cardv2
 */

/** Cap on inline list rows in cards. Beyond this we emit a "view all in app" hint. */
export const MAX_INLINE_ROWS = 10;

/**
 * Soft cap for the JSON-stringified card payload. Google Chat's hard limit
 * is 32KB per message; we stay well under it so margin remains for system
 * fields the SDK adds on the wire.
 */
export const MAX_CARD_BYTES = 30_000;

export interface DecoratedTextWidget {
  decoratedText: {
    topLabel?: string;
    text: string;
    bottomLabel?: string;
    wrapText?: boolean;
    startIcon?: { knownIcon: string };
  };
}

export interface TextParagraphWidget {
  textParagraph: { text: string };
}

export interface DividerWidget {
  divider: Record<string, never>;
}

export interface ButtonListWidget {
  buttonList: {
    buttons: ChatButton[];
  };
}

export interface ChatButton {
  text: string;
  onClick: {
    openLink?: { url: string };
    action?: {
      function: string;
      parameters?: Array<{ key: string; value: string }>;
    };
  };
}

export type CardWidget =
  | DecoratedTextWidget
  | TextParagraphWidget
  | DividerWidget
  | ButtonListWidget;

export interface CardSection {
  header?: string;
  widgets: CardWidget[];
  collapsible?: boolean;
  uncollapsibleWidgetsCount?: number;
}

export interface CardV2 {
  cardId: string;
  card: {
    header?: { title: string; subtitle?: string };
    sections: CardSection[];
  };
}

export interface CardV2Message {
  text?: string;
  cardsV2: CardV2[];
}

export const widget = {
  decoratedText(opts: DecoratedTextWidget['decoratedText']): DecoratedTextWidget {
    return { decoratedText: opts };
  },
  textParagraph(text: string): TextParagraphWidget {
    return { textParagraph: { text } };
  },
  divider(): DividerWidget {
    return { divider: {} };
  },
  buttonList(buttons: ChatButton[]): ButtonListWidget {
    return { buttonList: { buttons } };
  },
};
