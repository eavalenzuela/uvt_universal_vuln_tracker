export function createWidgetRegistry(renderers = {}) {
  return {
    get(widgetId) {
      return renderers[widgetId] || null;
    },
  };
}
