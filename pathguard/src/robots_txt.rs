use lazy_static::lazy_static;
use std::borrow::Cow;

use crate::ARGS;

lazy_static! {
	pub static ref DEFAULT_ROBOTS: Box<str> = format!(
		"User-agent: *\nDisallow: {dashboard}",
		dashboard = ARGS.dashboard
	)
	.into_boxed_str();
}

pub fn update(robots: &str) -> Cow<'static, str> {
	update_or(robots, &*DEFAULT_ROBOTS, &*ARGS.dashboard)
}

fn update_or(robots: &str, default: &'static str, dashboard: &'static str) -> Cow<'static, str> {
	let robots = robots.trim();
	let mut lines = robots.lines();
	let mut chars = 0;
	let mut updated = String::new();
	let mut seen_star = false;
	while let Some(line) = lines.next() {
		if line.trim().to_lowercase().starts_with("user-agent") {
			updated.push_str("User-agent: ");
			let agent = line.split(":").nth(1).map(|str| str.trim()).unwrap_or("*");
			if agent == "*" {
				seen_star = true;
			}
			updated.push_str(agent);
			updated.push_str("\nDisallow: ");
			updated.push_str(dashboard);
			updated.push_str("\n");
		} else {
			updated.push_str(&robots[chars..chars + line.len()]);
		}
		// have to add the \n as well
		chars += line.len() + 1;
	}
	if updated.is_empty() {
		return Cow::Borrowed(default);
	}
	if !seen_star {
		updated.push_str("\n\n");
		updated.push_str(default);
	}
	Cow::Owned(updated)
}

#[cfg(test)]
mod tests {
	use std::borrow::Cow;

	use super::update_or;
	use const_format::formatcp;

	#[test]
	fn robots() {
		static DASHBOARD: &str = "/pathguard";
		static DEFAULT_ROBOTS: &str = formatcp!("User-agent: *\nDisallow: {DASHBOARD}");
		fn update(robots: &str) -> Cow<'static, str> {
			update_or(robots, DEFAULT_ROBOTS, DASHBOARD)
		}
		assert_eq!(update(""), DEFAULT_ROBOTS);
		{
			const INPUT: &str = "foo";
			assert_eq!(update(INPUT), formatcp!("{INPUT}\n\n{DEFAULT_ROBOTS}"));
		}
		{
			const INPUT: &str = "USER-AGENT: amogus\nDisallow: /foo";
			assert_eq!(
				update(INPUT),
				formatcp!(
					"User-agent: amogus\nDisallow: {DASHBOARD}\nDisallow: /foo\n\n{DEFAULT_ROBOTS}"
				)
			);
		}
		{
			const INPUT: &str = "UsEr-AgEnT: *\nDisallow: /foo";
			assert_eq!(
				update(INPUT),
				formatcp!("User-agent: *\nDisallow: {DASHBOARD}\nDisallow: /foo")
			)
		}
	}
}
