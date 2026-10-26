/* Illustrative playback only. No network access, dispatch or provider calls. */
export function initializePhantomWorld(root) {
  if (!root || root.dataset.initialized === 'true') return;
  root.dataset.initialized = 'true';
  const stages = [
    { name: 'Investigate', agent: 'scout', title: 'Find the cause before changing the code', description: 'Scout follows a reported retry failure to a small, reproducible case. The task and its context stay visible while the rest of the team gets ready.', evidence: 'A reproducible case and a short explanation of the suspected cause.' },
    { name: 'Build', agent: 'builder', title: 'Turn the finding into a focused patch', description: 'Builder prepares a change against the same task. The handoff carries the finding and the files involved, so the work can move forward without repeating the investigation.', evidence: 'A proposed patch, its diff and the reasoning behind the change.' },
    { name: 'Verify', agent: 'reviewer', title: 'Check the behavior that matters', description: 'Reviewer checks the reproduction and the affected behavior. Passing a test is evidence about that check; it does not mean the change has already shipped.', evidence: 'The test result, what was checked and anything still unverified.' },
    { name: 'Review', agent: 'reviewer', title: 'Bring the work back with its evidence', description: 'The patch, checks and remaining questions come together in one inspectable result. You can redirect the task, discuss a tradeoff or decide what should happen next.', evidence: 'A reviewable result with the diff, checks and open questions together.' },
    { name: 'Result', agent: 'builder', title: 'A complete demo result, ready to inspect', description: 'This illustrative task has reached its final step. In your connected workbench, you would inspect the actual run and its recorded outcome here.', evidence: 'Demo complete. No repository changed, tests ran or production release occurred.' },
  ];
  const roles = { scout: { name: 'Scout', task: 'Investigate the retry failure', context: 'Report and reproduction' }, builder: { name: 'Builder', task: 'Prepare a focused patch', context: 'Finding and affected files' }, reviewer: { name: 'Reviewer', task: 'Verify and review the change', context: 'Diff and applicable checks' } };
  const modeDescriptions = {
    with: 'You stay in the conversation and guide each handoff.',
    for: 'The illustrative team moves through the task and brings you the result.',
  };
  const controller = new window.AbortController();
  const options = { signal: controller.signal };
  const find = selector => root.querySelector(selector);
  const play = find('[data-action="play"]');
  const status = find('[data-playback-status]');
  let resource = 'subscription';
  const resourceDescriptions = {
    subscription: 'Connect your supported CLI accounts. Each account keeps its own subscription window and usage reading.',
    api: 'Bring API access or reported credit balances. Paid credits stay separate from subscription allowances and their reset times.',
    local: 'Use tool-capable local models on your own computer. Model readiness, context and performance come from the local runtime.',
    tools: 'Connect configured MCP servers and CLIs to give agents tools for deployment, databases and your engineering workflow.',
  };
  let mode = 'for';
  let step = 0;
  let agent = stages[0].agent;
  let playing = false;
  let timer = null;
  let observer = null;
  let inView = true;

  function clearTimer() {
    if (timer !== null) window.clearTimeout(timer);
    timer = null;
  }
  function render(note = '') {
    const stage = stages[step];
    const role = roles[agent];
    root.dataset.stage = String(step);
    root.dataset.mode = mode;
    root.dataset.playing = String(playing);
    root.dataset.resource = resource;
    root.dataset.activeAgent = stages[step].agent;
    root.querySelectorAll('[data-resource]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.resource === resource)));
    root.querySelectorAll('[data-provider-kind]').forEach(tile => { tile.dataset.highlighted = String(tile.dataset.providerKind.split(' ').includes(resource)); });
    find('[data-resource-description]').textContent = resourceDescriptions[resource];
    root.querySelectorAll('[data-mode]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.mode === mode)));
    root.querySelectorAll('[data-agent]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.agent === agent)));
    root.querySelectorAll('[data-step]').forEach(button => {
      if (Number(button.dataset.step) === step) button.setAttribute('aria-current', 'step');
      else button.removeAttribute('aria-current');
    });
    find('[data-mode-description]').textContent = modeDescriptions[mode];
    find('[data-workflow-label]').textContent = mode === 'with' ? 'Guided workflow · a retry fix' : 'Delegated workflow · a retry fix';
    find('[data-stage-title]').textContent = stage.title;
    find('[data-stage-description]').textContent = stage.description;
    find('[data-role-name]').textContent = role.name;
    find('[data-role-task]').textContent = role.task;
    find('[data-role-context]').textContent = role.context;
    find('[data-evidence]').textContent = stage.evidence;
    find('[data-token]').textContent = stage.name === 'Result' ? 'Demo result' : 'Retry fix';
    play.textContent = playing ? 'Pause replay' : step === stages.length - 1 ? 'Replay demo' : step === 0 ? 'Play demo' : 'Resume replay';
    play.setAttribute('aria-pressed', String(playing));
    find('[data-action="next"]').disabled = step === stages.length - 1;
    status.textContent = `${step + 1} of ${stages.length} · ${stage.name}${note ? ` · ${note}` : playing ? ' · Playing' : ' · Ready'}`;
  }
  function pause(note = 'Paused') {
    playing = false;
    clearTimer();
    render(note);
  }
  function schedule() {
    clearTimer();
    if (!playing) return;
    timer = window.setTimeout(() => {
      timer = null;
      if (document.hidden || !inView) { pause('Paused while out of view'); return; }
      if (step < stages.length - 1) {
        step += 1;
        agent = stages[step].agent;
      }
      if (step === stages.length - 1) { pause('Replay complete'); return; }
      render();
      schedule();
    }, 2600);
  }
  root.addEventListener('click', event => {
    const button = event.target instanceof window.Element ? event.target.closest('button') : null;
    if (!button || !root.contains(button) || button.disabled) return;
    if (button.dataset.resource && Object.hasOwn(resourceDescriptions, button.dataset.resource)) {
      resource = button.dataset.resource;
      render('Resource view changed');
    } else if (button.dataset.mode && Object.hasOwn(modeDescriptions, button.dataset.mode)) {
      mode = button.dataset.mode;
      pause('Mode changed');
    } else if (button.dataset.agent && Object.hasOwn(roles, button.dataset.agent)) {
      agent = button.dataset.agent;
      pause('Agent selected');
    } else if (button.dataset.step !== undefined) {
      const selected = Number(button.dataset.step);
      if (!Number.isInteger(selected) || selected < 0 || selected >= stages.length) return;
      step = selected;
      agent = stages[step].agent;
      pause('Stage selected');
    } else if (button.dataset.action === 'play') {
      if (playing) { pause(); return; }
      if (document.hidden || !inView) { pause('Bring the demo into view to replay'); return; }
      if (step === stages.length - 1) step = 0;
      agent = stages[step].agent;
      playing = true;
      render();
      schedule();
    } else if (button.dataset.action === 'next') {
      step = Math.min(stages.length - 1, step + 1);
      agent = stages[step].agent;
      pause(step === stages.length - 1 ? 'Replay complete' : 'Next stage');
    } else if (button.dataset.action === 'restart') {
      step = 0;
      agent = stages[step].agent;
      pause('Reset');
    }
  }, options);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden && playing) pause('Paused in the background');
  }, options);
  if ('IntersectionObserver' in window) {
    observer = new window.IntersectionObserver(entries => {
      inView = entries.some(entry => entry.isIntersecting);
      if (!inView && playing) pause('Paused while out of view');
    });
    observer.observe(root);
  }
  function teardown() {
    playing = false;
    clearTimer();
    observer?.disconnect();
    observer = null;
    controller.abort();
    root.dataset.initialized = 'false';
    root.classList.remove('pw-enhanced');
    root.dataset.playing = 'false';
    root.querySelectorAll('button').forEach(button => { button.disabled = true; });
    status.textContent = 'Replay stopped.';
  }
  root.querySelectorAll('button').forEach(button => { button.disabled = false; });
  root.classList.add('pw-enhanced');
  render();
  return teardown;
}
