import { describe, expect, it } from 'vitest'
import { createRuntimeWorkflow, runRuntimeWorkflow } from '../src/index.js'

describe('@fides/runtime-effect boundary', () => {
  it('creates a plain workflow descriptor without Effect-specific protocol objects', async () => {
    const workflow = createRuntimeWorkflow({
      id: 'workflow-1',
      context: {
        query: {
          schema_version: 'fides.discovery_query.v1',
          id: 'query-1',
          capability: 'invoice.reconcile',
        },
      },
    })

    expect(workflow.steps).toContain('evaluate_policy')
    expect(workflow.context.query?.capability).toBe('invoice.reconcile')

    const result = await runRuntimeWorkflow(workflow, {
      async run(current) {
        return {
          ...current.context,
          evidenceEvents: [],
        }
      },
    })

    expect(result.evidenceEvents).toEqual([])
  })
})
