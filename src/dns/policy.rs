#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(super) struct Selection {
    pub map_mark: u32,
    pub default_mark: u32,
}

impl Selection {
    pub(super) const fn positioned_mark(self, mask: u32) -> u32 {
        let selected = self.map_mark & mask;
        if selected == 0 {
            self.default_mark & mask
        } else {
            selected
        }
    }

    pub(super) const fn routing_mark(self, mask: u32) -> u32 {
        self.positioned_mark(mask) >> mask.trailing_zeros()
    }
}

#[derive(Debug, Default)]
#[cfg(not(target_os = "linux"))]
pub(super) struct UnsupportedPlatformPolicy;

#[cfg(not(target_os = "linux"))]
impl UnsupportedPlatformPolicy {
    pub(super) async fn snapshot(&self, _client: std::net::IpAddr) -> anyhow::Result<Selection> {
        anyhow::bail!("wlt-dns policy lookup requires Linux nftables support")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_marks_use_configured_masks_and_per_mask_defaults() {
        let selection = Selection {
            map_mark: 0xab00_0000,
            default_mark: 0x0000_1200,
        };
        assert_eq!(selection.routing_mark(0xff00_0000), 0xab);
        assert_eq!(selection.routing_mark(0x0000_ff00), 0x12);
        assert_eq!(selection.routing_mark(0x0000_00ff), 0);
        assert_eq!(selection.positioned_mark(0xff00_0000), 0xab00_0000);
    }
}
