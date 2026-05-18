# zoraxy-ua-blocker

A Zoraxy v3 plugin that blocks incoming HTTP requests whose `User-Agent`
header contains any string from a user-managed blocklist.

Matching is **case-insensitive substring** matching. Blocked requests
receive HTTP **403 Forbidden**.

## Build

    go mod tidy
    go build -o zoraxy-ua-blocker

## Install

1. Create `plugins/zoraxy-ua-blocker/` inside your Zoraxy data directory.
2. Place the compiled `zoraxy-ua-blocker` binary inside it.
3. Restart Zoraxy.
4. Open the Plugin Manager UI, find **User-Agent Blocker**, and assign its
   tag to every proxy host you want protected. (Tip: create one shared tag
   like `global` and apply it everywhere.)
5. Open the plugin UI from the Plugin Manager and add entries such as
   `wget`, `curl`, `spider`, `Googlebot`.

## Storage

The blocklist is persisted to `uablocker_data.json` next to the plugin
binary. Safe to back up or edit by hand while the plugin is stopped.
