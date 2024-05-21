use std::fs::File;
use std::io::BufWriter;
use std::time::SystemTime;

use memory_stats::memory_stats;
use tracing_flame::FlameLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;
use cilium::structured::Context;

fn setup_global_subscriber() -> impl Drop {
	let file = File::create("./trace.folded").unwrap();
	let flame_layer = FlameLayer::new(BufWriter::new(file)).with_file_and_line(false);
	let guard = flame_layer.flush_on_drop();

	let subscriber = Registry::default()
		.with(flame_layer);

	tracing::subscriber::set_global_default(subscriber).expect("Could not set global default");
	guard
}

fn main() {
	let _guard = setup_global_subscriber();

	let start = SystemTime::now();
	let ctx = Context::new([
		"C:/Program Files/dotnet/sdk/8.0.204"
	]);
	
	println! {
		"Schema time: {:?}, RAM: {}MB",
		start.elapsed().unwrap(),
		memory_stats().unwrap().virtual_mem as f32 / 1000000.0,
	}

	println!("{:#?}", ctx);
}
