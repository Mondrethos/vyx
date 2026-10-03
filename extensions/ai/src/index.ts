import { defineExtension, ui } from '@vyx/extension-sdk';

// Current Vyx opens this package's commands in its native AI surface without
// running guest code. Older API-1 hosts can still explain the version boundary;
// this module deliberately has no provider access or credential fields.
export default defineExtension({
  onEvent() {
    return {
      view: ui.detail({
        title: 'Vyx AI requires native AI support',
        fields: [
          { label: 'Upgrade Vyx', value: 'This host launched a guest view instead of the native AI panel. Update Vyx to a release with Vyx AI support, then open this command again.' },
          { label: 'Credentials', value: 'Never enter API keys or subscription tokens in extension forms. Vyx AI uses host-owned provider settings.' },
          { label: 'Provider requests', value: 'Missing a provider? Open an issue to request support.' },
          { label: 'Request a provider', value: 'https://github.com/Mondrethos/vyx/issues/new' },
          { label: 'Issue privacy', value: 'Include the provider name, public API/authentication documentation, and desired capabilities. Do not include API keys, tokens, server logs, or credentials.' },
        ],
      }),
    };
  },
});
