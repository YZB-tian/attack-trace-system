export function selectTask(current: string, events: { task_id: string }[]): string {
  return current || events[0]?.task_id || '';
}
