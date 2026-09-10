import assert from 'node:assert/strict';
import test from 'node:test';
import { selectTask } from '../src/task-selection.ts';

test('selects real data task without a demonstration fallback', () => {
  assert.equal(selectTask('', []), '');
  assert.equal(selectTask('', [{task_id: 'task_lab'}]), 'task_lab');
  assert.equal(selectTask('task_selected', [{task_id: 'task_lab'}]), 'task_selected');
});
