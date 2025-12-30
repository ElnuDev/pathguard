// @generated automatically by Diesel CLI.

diesel::table! {
	activities (id) {
		id -> Nullable<Integer>,
		timestamp -> Timestamp,
		user -> Nullable<Text>,
		ip -> Text,
		path -> Text,
		allowed -> Bool,
	}
}

diesel::table! {
	groups (name) {
		sort -> Integer,
		name -> Text,
	}
}

diesel::table! {
	rules (group, path) {
		sort -> Integer,
		group -> Text,
		allowed -> Nullable<Bool>,
		path -> Text,
	}
}

diesel::table! {
	user_groups (user, group) {
		user -> Text,
		group -> Text,
	}
}

diesel::table! {
	users (name) {
		name -> Text,
		password -> Text,
		created -> Timestamp,
		deleted -> Bool,
	}
}

diesel::joinable!(activities -> users (user));
diesel::joinable!(rules -> groups (group));
diesel::joinable!(user_groups -> groups (group));
diesel::joinable!(user_groups -> users (user));

diesel::allow_tables_to_appear_in_same_query!(activities, groups, rules, user_groups, users,);
