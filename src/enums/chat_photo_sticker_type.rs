/// What a sticker used as a chat photo is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChatPhotoStickerType {
    /// A regular or mask sticker, from a sticker set.
    RegularOrMask,
    CustomEmoji,
}
