use super::edit_inline_text::EditInlineText;
use crate::Client;
use crate::types::{InlineMessageId, MessageText, Text};

impl Client {
    /// An empty caption removes it.
    pub fn edit_inline_caption(
        &self,
        inline_message_id: InlineMessageId,
        caption: impl Into<Text>,
    ) -> EditInlineText<'_> {
        self.edit_inline_text(inline_message_id, MessageText::Text(caption.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::edit_inline_text::tests::id;
    use crate::Client;
    use crate::raw::functions::messages::EditInlineBotMessage;
    use crate::raw::{Serializable, base, types};

    #[tokio::test]
    async fn inline_caption_edits_message_only() {
        let (client, mut rx) = Client::recording();
        let _ = client.edit_inline_caption(id(), "new").show_caption_above_media().await;
        let msg = types::InputBotInlineMessageID64 { dc_id: 2, owner_id: 5, id: 6, access_hash: 7 };
        let expected = EditInlineBotMessage {
            no_webpage: false,
            invert_media: true,
            id: base::InputBotInlineMessageID::InputBotInlineMessageID64(Box::new(msg)),
            message: Some("new".into()),
            media: None,
            reply_markup: None,
            entities: None,
            rich_message: None,
        };
        assert_eq!(rx.try_recv().unwrap(), expected.to_bytes());
    }
}
