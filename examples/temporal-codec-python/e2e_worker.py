"""Worker for the local end-to-end check. Run it under `phantom exec`.

It reports only whether each requested variable holds a Phantom placeholder
(prefix `phm_`), never a value.
"""

import asyncio
import os
import sys

from temporalio.worker import Worker

from e2e_common import TASK_QUEUE, connect
from e2e_workflow import GreetingWorkflow, compose_greeting


async def main() -> None:
    for name in sys.argv[1:]:
        value = os.environ.get(name)
        state = "missing" if value is None else ("placeholder" if value.startswith("phm_") else "NOT a placeholder")
        print(f"{name}: {state}", flush=True)
    client = await connect()
    worker = Worker(client, task_queue=TASK_QUEUE, workflows=[GreetingWorkflow], activities=[compose_greeting])
    print("worker running", flush=True)
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
