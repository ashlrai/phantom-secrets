pub mod helpers;
pub mod params;

mod generate;
pub use generate::{generate_secret, GenerationReceipt};
pub use phantom_core::secret_metadata::get as get_metadata;
