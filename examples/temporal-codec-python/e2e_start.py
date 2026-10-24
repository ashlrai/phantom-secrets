"""Start one GreetingWorkflow and print its result. Fake input only."""

import asyncio
import sys

from e2e_common import TASK_QUEUE, connect
from e2e_workflow import GreetingWorkflow


async def main() -> None:
    workflow_id, name = sys.argv[1], sys.argv[2]
    client = await connect()
    result = await client.execute_workflow(GreetingWorkflow.run, name, id=workflow_id, task_queue=TASK_QUEUE)
    print(result)


if __name__ == "__main__":
    asyncio.run(main())
