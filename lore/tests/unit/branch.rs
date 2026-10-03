// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore::branch::*;
use lore::interface::LoreString;
use lore_revision::interface::LoreArray;

/// An old client's payload is this one without the field it never knew, so
/// it is built by removing the field rather than by transcribing the shape.
fn without_inherit_metadata<T: serde::Serialize>(args: &T) -> serde_json::Value {
    let mut payload = serde_json::to_value(args).expect("args must serialise");
    payload
        .as_object_mut()
        .expect("args serialise to an object")
        .remove("inherit_metadata")
        .expect("the field must be present before it is removed");
    payload
}

#[test]
fn merge_start_args_old_payload_missing_inherit_metadata_uses_default() {
    // Old IPC client payload with no inherit_metadata field. The new field
    // must be `#[serde(default)]` so old clients keep working.
    let payload = without_inherit_metadata(&LoreBranchMergeStartArgs {
        branch: "feature".into(),
        message: "merge feature".into(),
        no_commit: 0,
        link: Default::default(),
        ignore_links: 0,
        inherit_metadata: LoreArray::from_vec(vec![LoreString::from("change-request")]),
    });

    let args: LoreBranchMergeStartArgs =
        serde_json::from_value(payload).expect("old payload must deserialise");

    assert_eq!(args.branch.as_str(), "feature");
    assert_eq!(args.message.as_str(), "merge feature");
    assert!(args.inherit_metadata.as_slice().is_empty());
}

#[test]
fn merge_into_args_old_payload_missing_inherit_metadata_uses_default() {
    let payload = without_inherit_metadata(&LoreBranchMergeIntoArgs {
        branch: "main".into(),
        branch_id: Default::default(),
        message: "merge into main".into(),
        link: Default::default(),
        ignore_links: 0,
        inherit_metadata: LoreArray::from_vec(vec![LoreString::from("*")]),
    });

    let args: LoreBranchMergeIntoArgs =
        serde_json::from_value(payload).expect("old payload must deserialise");

    assert_eq!(args.branch.as_str(), "main");
    assert!(args.inherit_metadata.as_slice().is_empty());
}

#[test]
fn archive_args_old_payload_missing_cascade_fields_uses_defaults() {
    // Old IPC client payload with no layer or link fields. The new fields
    // must be `#[serde(default)]` so old clients keep working.
    let payload = r#"{ "branch": "feature" }"#;

    let args: LoreBranchArchiveArgs =
        serde_json::from_str(payload).expect("old payload must deserialise");

    assert_eq!(args.branch.as_str(), "feature");
    assert_eq!(args.layer.as_str(), "");
    assert_eq!(args.include_layers, 0);
    assert_eq!(args.link.as_str(), "");
    assert_eq!(args.include_links, 0);
}

#[test]
fn archive_args_layer_payload_missing_link_fields_uses_defaults() {
    // A client that knows the layer fields but not the link ones.
    let payload = r#"{ "branch": "feature", "layer": "lay", "include_layers": 1 }"#;

    let args: LoreBranchArchiveArgs =
        serde_json::from_str(payload).expect("layer payload must deserialise");

    assert_eq!(args.layer.as_str(), "lay");
    assert_eq!(args.include_layers, 1);
    assert_eq!(args.link.as_str(), "");
    assert_eq!(args.include_links, 0);
}

#[test]
fn cascade_scope_maps_each_field_combination() {
    assert!(matches!(
        CascadeScope::new(&LoreString::from(""), 0, "link", "include_links"),
        Ok(CascadeScope::OuterOnly)
    ));
    assert!(matches!(
        CascadeScope::new(&LoreString::from(""), 1, "link", "include_links"),
        Ok(CascadeScope::All)
    ));
    assert!(matches!(
        CascadeScope::new(&LoreString::from("lnk"), 0, "link", "include_links"),
        Ok(CascadeScope::Single(path)) if path == "lnk"
    ));
}

#[test]
fn cascade_scope_rejects_a_path_together_with_include_all() {
    let scope = CascadeScope::new(&LoreString::from("lnk"), 1, "link", "include_links");

    let err = scope.expect_err("a path with include_all must be refused");
    assert!(
        err.to_string().contains("link and include_links"),
        "expected the conflicting fields to be named, got: {err}"
    );
}
