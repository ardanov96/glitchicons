"""
GLITCHICONS ⬡ — RL Agent Module
Decepticons Siege Division

Reinforcement Learning agent that learns the optimal mutation
strategy per target — without requiring PyTorch or GPU.

Uses Q-Learning (tabular) — lightweight, fast, effective.
No heavy dependencies: pure Python + numpy only.

Architecture:
  State  = coverage bucket + crash rate + exec speed tier
  Action = mutation strategy (havoc, bit_flip, splice, etc.)
  Reward = new edges found + crash bonus - timeout penalty

The agent learns: "for THIS target, THESE strategies yield
more coverage" — and adapts in real time during fuzzing.
"""

import json
import math
import time
import random
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.text import Text

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

console = Console()


# ══════════════════════════════════════════════════════════════════════════════
# MUTATION STRATEGIES (AFL++ compatible)
# ══════════════════════════════════════════════════════════════════════════════

STRATEGIES = [
    "havoc",          # Random mutations — AFL++ default powerhouse
    "splice",         # Combine two corpus entries
    "bit_flip",       # Flip individual bits
    "byte_flip",      # Flip bytes
    "arithmetics",    # Add/subtract small integers
    "interest",       # Replace with interesting values (0, -1, MAX_INT)
    "overwrite",      # Overwrite bytes with random data
    "insert",         # Insert random bytes
    "delete",         # Delete random bytes
    "llm_guided",     # Use LLM to generate targeted mutations (Glitchicons exclusive)
]

# AFL++ strategy flags mapping
AFL_STRATEGY_FLAGS = {
    "havoc":      ["-p", "fast"],
    "splice":     ["-p", "fast"],      # Splice is always on in AFL++
    "bit_flip":   ["-D"],              # Enable deterministic
    "byte_flip":  ["-D"],
    "arithmetics":["-D"],
    "interest":   ["-D"],
    "overwrite":  [],                  # Default havoc covers this
    "insert":     [],
    "delete":     [],
    "llm_guided": [],                  # Glitchicons-specific, handled separately
}


# ══════════════════════════════════════════════════════════════════════════════
# STATE ENCODER
# ══════════════════════════════════════════════════════════════════════════════

class StateEncoder:
    """
    Encodes fuzzing session state into a discrete Q-table key.

    State dimensions:
    - coverage_bucket: 0-9 (0-10%, 10-20%, ..., 90-100%)
    - crash_rate: 0=none, 1=low(<1%), 2=medium(1-5%), 3=high(>5%)
    - speed_tier: 0=slow(<100/s), 1=medium, 2=fast(>1000/s)
    - cycle: 0=early(<3), 1=mid(3-10), 2=late(>10)
    """

    @staticmethod
    def encode(
        coverage_pct: float,
        total_execs: int,
        crashes: int,
        exec_speed: float,
        cycles_done: int,
    ) -> tuple:
        crash_rate = crashes / max(total_execs, 1)

        cov_bucket = min(int(coverage_pct / 10), 9)

        if crash_rate == 0:
            crash_tier = 0
        elif crash_rate < 0.01:
            crash_tier = 1
        elif crash_rate < 0.05:
            crash_tier = 2
        else:
            crash_tier = 3

        if exec_speed < 100:
            speed_tier = 0
        elif exec_speed < 1000:
            speed_tier = 1
        else:
            speed_tier = 2

        if cycles_done < 3:
            cycle_tier = 0
        elif cycles_done < 10:
            cycle_tier = 1
        else:
            cycle_tier = 2

        return (cov_bucket, crash_tier, speed_tier, cycle_tier)


# ══════════════════════════════════════════════════════════════════════════════
# Q-LEARNING AGENT
# ══════════════════════════════════════════════════════════════════════════════

class QLearningAgent:
    """
    Tabular Q-Learning agent for mutation strategy selection.

    Q-table: state → action → expected_reward
    Updated after each fuzzing interval via Bellman equation.

    Hyperparameters:
    - alpha (learning rate): 0.1 — how fast to update Q values
    - gamma (discount):      0.9 — how much future rewards matter
    - epsilon (exploration):  starts high, decays over time
    """

    def __init__(
        self,
        strategies: list[str] = None,
        alpha: float = 0.1,
        gamma: float = 0.9,
        epsilon_start: float = 0.9,
        epsilon_end: float = 0.1,
        epsilon_decay: float = 0.95,
        memory_file: str = "~/.glitchicons/rl_agent.json",
    ):
        self.strategies = strategies or STRATEGIES
        self.n_actions = len(self.strategies)
        self.alpha = alpha
        self.gamma = gamma
        self.epsilon = epsilon_start
        self.epsilon_end = epsilon_end
        self.epsilon_decay = epsilon_decay
        self.memory_file = Path(memory_file).expanduser()
        self.memory_file.parent.mkdir(parents=True, exist_ok=True)

        # Q-table: dict of state_tuple → list of Q values per action
        self.q_table: dict = {}

        # Stats
        self.total_steps = 0
        self.total_episodes = 0
        self.action_counts = {s: 0 for s in self.strategies}
        self.action_rewards = {s: [] for s in self.strategies}

        self._load()

    def _load(self):
        """Load Q-table from disk."""
        if self.memory_file.exists():
            try:
                with open(self.memory_file) as f:
                    data = json.load(f)
                # Restore Q-table (keys were stringified)
                self.q_table = {
                    eval(k): v for k, v in data.get("q_table", {}).items()
                }
                self.epsilon = data.get("epsilon", self.epsilon)
                self.total_steps = data.get("total_steps", 0)
                self.total_episodes = data.get("total_episodes", 0)
                self.action_counts = data.get(
                    "action_counts", {s: 0 for s in self.strategies}
                )
                console.print(
                    f"[dim]⬡ Agent loaded: {len(self.q_table)} states, "
                    f"{self.total_steps} steps, ε={self.epsilon:.2f}[/dim]"
                )
            except Exception:
                pass

    def _save(self):
        """Persist Q-table to disk."""
        data = {
            "q_table": {str(k): v for k, v in self.q_table.items()},
            "epsilon": self.epsilon,
            "total_steps": self.total_steps,
            "total_episodes": self.total_episodes,
            "action_counts": self.action_counts,
            "saved_at": datetime.now().isoformat(),
        }
        with open(self.memory_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _get_q_values(self, state: tuple) -> list[float]:
        """Get Q values for a state, initializing if unseen."""
        if state not in self.q_table:
            # Optimistic initialization — encourages exploration
            self.q_table[state] = [0.5] * self.n_actions
        return self.q_table[state]

    def select_action(self, state: tuple) -> tuple[int, str]:
        """
        Epsilon-greedy action selection.

        With probability epsilon: explore (random strategy)
        Otherwise: exploit (best known strategy for this state)
        """
        if random.random() < self.epsilon:
            # Explore: random strategy
            idx = random.randint(0, self.n_actions - 1)
            mode = "explore"
        else:
            # Exploit: best Q value
            q_vals = self._get_q_values(state)
            idx = q_vals.index(max(q_vals))
            mode = "exploit"

        strategy = self.strategies[idx]
        self.action_counts[strategy] = self.action_counts.get(strategy, 0) + 1
        return idx, strategy

    def update(
        self,
        state: tuple,
        action_idx: int,
        reward: float,
        next_state: tuple,
    ):
        """
        Q-value update via Bellman equation:
        Q(s,a) ← Q(s,a) + α[r + γ·max_a'Q(s',a') - Q(s,a)]
        """
        q_current = self._get_q_values(state)[action_idx]
        q_next_max = max(self._get_q_values(next_state))

        # Bellman update
        q_new = q_current + self.alpha * (
            reward + self.gamma * q_next_max - q_current
        )
        self.q_table[state][action_idx] = q_new

        # Track reward per action
        strategy = self.strategies[action_idx]
        self.action_rewards.setdefault(strategy, []).append(reward)
        if len(self.action_rewards[strategy]) > 100:
            self.action_rewards[strategy] = self.action_rewards[strategy][-100:]

        self.total_steps += 1

        # Decay epsilon
        if self.epsilon > self.epsilon_end:
            self.epsilon *= self.epsilon_decay

    def best_strategy_for_state(self, state: tuple) -> str:
        """Return the currently best-known strategy for a state."""
        q_vals = self._get_q_values(state)
        idx = q_vals.index(max(q_vals))
        return self.strategies[idx]

    def get_strategy_stats(self) -> list[dict]:
        """Return stats per strategy sorted by average reward."""
        stats = []
        for strategy in self.strategies:
            rewards = self.action_rewards.get(strategy, [])
            avg_reward = sum(rewards) / len(rewards) if rewards else 0.0
            stats.append({
                "strategy": strategy,
                "count": self.action_counts.get(strategy, 0),
                "avg_reward": round(avg_reward, 3),
                "total_reward": round(sum(rewards), 3),
            })
        return sorted(stats, key=lambda x: x["avg_reward"], reverse=True)

    def print_stats(self):
        """Pretty print agent statistics."""
        console.print(f"\n[bold purple]⬡ RL AGENT STATS[/bold purple]")
        console.print(f"  Episodes  : {self.total_episodes}")
        console.print(f"  Steps     : {self.total_steps}")
        console.print(f"  Epsilon   : {self.epsilon:.3f} "
                      f"[dim](exploration rate)[/dim]")
        console.print(f"  States    : {len(self.q_table)} learned\n")

        table = Table(show_header=True, header_style="bold purple", box=None)
        table.add_column("Strategy", style="cyan", width=16)
        table.add_column("Used", width=8)
        table.add_column("Avg Reward", width=12)
        table.add_column("Assessment", width=20)

        for s in self.get_strategy_stats():
            if s["count"] == 0:
                assessment = "[dim]not tried yet[/dim]"
            elif s["avg_reward"] > 0.5:
                assessment = "[green]★ highly effective[/green]"
            elif s["avg_reward"] > 0.1:
                assessment = "[yellow]○ moderate[/yellow]"
            else:
                assessment = "[red]✗ low yield[/red]"

            table.add_row(
                s["strategy"],
                str(s["count"]),
                str(s["avg_reward"]),
                assessment,
            )
        console.print(table)


# ══════════════════════════════════════════════════════════════════════════════
# REWARD CALCULATOR
# ══════════════════════════════════════════════════════════════════════════════

class RewardCalculator:
    """
    Calculates reward signal from AFL++ state transitions.

    Reward components:
    + New edges/paths discovered (main signal)
    + Crash found (big bonus)
    + Execution speed maintained (efficiency)
    - Timeout penalty (strategy too slow)
    - No progress penalty (strategy stalled)
    """

    @staticmethod
    def calculate(
        prev_paths: int,
        curr_paths: int,
        prev_crashes: int,
        curr_crashes: int,
        exec_speed: float,
        timeouts: int,
        interval_seconds: float,
    ) -> float:
        reward = 0.0

        # New paths discovered — primary reward
        new_paths = curr_paths - prev_paths
        reward += new_paths * 2.0

        # Crash found — big bonus
        new_crashes = curr_crashes - prev_crashes
        reward += new_crashes * 10.0

        # Speed reward — reward efficiency
        if exec_speed > 1000:
            reward += 0.3
        elif exec_speed > 100:
            reward += 0.1

        # Timeout penalty
        reward -= timeouts * 0.5

        # No progress penalty
        if new_paths == 0 and new_crashes == 0:
            reward -= 0.2

        return round(reward, 4)


# ══════════════════════════════════════════════════════════════════════════════
# AFL++ STATS READER
# ══════════════════════════════════════════════════════════════════════════════

class AFLStatsReader:
    """Read and parse AFL++ fuzzer_stats in real time."""

    def __init__(self, afl_output_dir: str):
        self.afl_dir = Path(afl_output_dir)
        self._stats_path = self.afl_dir / "default" / "fuzzer_stats"
        if not self._stats_path.exists():
            self._stats_path = self.afl_dir / "fuzzer_stats"

    def read(self) -> dict:
        """Read current AFL++ stats."""
        if not self._stats_path.exists():
            return {}
        try:
            stats = {}
            with open(self._stats_path) as f:
                for line in f:
                    if ":" in line:
                        k, _, v = line.partition(":")
                        stats[k.strip()] = v.strip()
            return stats
        except Exception:
            return {}

    def get_state_metrics(self) -> dict:
        """Extract metrics relevant for RL state encoding."""
        raw = self.read()
        return {
            "paths_found": int(raw.get("paths_found", 0)),
            "saved_crashes": int(raw.get("saved_crashes", 0)),
            "total_execs": int(raw.get("execs_done", 0)),
            "exec_speed": float(raw.get("execs_per_sec", 0)),
            "cycles_done": int(raw.get("cycles_done", 0)),
            "total_tmouts": int(raw.get("saved_hangs", 0)),
            "bitmap_cvg": raw.get("bitmap_cvg", "0.00%"),
        }

    def get_coverage_pct(self) -> float:
        """Parse bitmap coverage percentage."""
        raw = self.read()
        cvg_str = raw.get("bitmap_cvg", "0.00%")
        try:
            return float(cvg_str.replace("%", "").split()[0])
        except Exception:
            return 0.0


# ══════════════════════════════════════════════════════════════════════════════
# RL FUZZING ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

class RLFuzzingOrchestrator:
    """
    Orchestrates AFL++ with RL-guided strategy selection.

    Runs AFL++ in intervals, reads coverage feedback,
    updates Q-table, selects next mutation strategy.

    This is what makes Glitchicons unique:
    Every fuzzing session makes the next one smarter.
    """

    def __init__(
        self,
        target_binary: str,
        corpus_dir: str,
        output_dir: str,
        interval_seconds: int = 60,
        total_duration: int = 3600,
        model: str = "qwen2.5-coder:3b",
    ):
        self.target = Path(target_binary)
        self.corpus = Path(corpus_dir)
        self.output = Path(output_dir)
        self.interval = interval_seconds
        self.total_duration = total_duration
        self.model = model

        self.output.mkdir(parents=True, exist_ok=True)

        self.agent = QLearningAgent()
        self.encoder = StateEncoder()
        self.reward_calc = RewardCalculator()
        self.stats_reader = AFLStatsReader(str(self.output))

        self.afl_process: Optional[subprocess.Popen] = None
        self.episode_log: list[dict] = []

    def _start_afl(self, strategy: str, resume: bool = False) -> subprocess.Popen:
        """Start AFL++ with given strategy flags."""
        flags = AFL_STRATEGY_FLAGS.get(strategy, [])

        cmd = ["afl-fuzz",
               "-i", str(self.corpus) if not resume else "-",
               "-o", str(self.output)]
        cmd.extend(flags)
        cmd.extend(["--", str(self.target), "@@"])

        console.print(f"[dim]⬡ Starting AFL++: {' '.join(cmd)}[/dim]")

        return subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def _stop_afl(self):
        """Stop running AFL++ process."""
        if self.afl_process and self.afl_process.poll() is None:
            self.afl_process.terminate()
            try:
                self.afl_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.afl_process.kill()
            self.afl_process = None

    def _get_current_state(self, metrics: dict) -> tuple:
        """Encode current metrics into RL state."""
        return self.encoder.encode(
            coverage_pct=self.stats_reader.get_coverage_pct(),
            total_execs=metrics.get("total_execs", 0),
            crashes=metrics.get("saved_crashes", 0),
            exec_speed=metrics.get("exec_speed", 0),
            cycles_done=metrics.get("cycles_done", 0),
        )

    def _generate_llm_seeds(self, uncovered_hint: str = ""):
        """Use LLM to generate targeted seeds for uncovered paths."""
        try:
            import ollama
            prompt = (
                f"Generate 5 malformed inputs targeting uncovered code paths. "
                f"Context: {uncovered_hint or 'binary fuzzing target'}. "
                f"Return only the inputs, one per line."
            )
            r = ollama.chat(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                options={"temperature": 0.9, "num_predict": 512}
            )
            seeds = [l.strip() for l in r["message"]["content"].split("\n")
                     if l.strip() and not l.startswith("```")]
            for i, seed in enumerate(seeds[:5]):
                seed_file = self.corpus / f"rl_seed_{int(time.time())}_{i}.txt"
                seed_file.write_text(seed)
            console.print(f"  [purple]⬡ LLM added {len(seeds[:5])} targeted seeds[/purple]")
        except Exception as e:
            console.print(f"  [dim]LLM seed gen skipped: {e}[/dim]")

    def run(self) -> dict:
        """
        Run RL-guided fuzzing session.

        Returns summary of the session including:
        - strategies used and their effectiveness
        - coverage achieved
        - crashes found
        - Q-table state
        """
        if not shutil.which("afl-fuzz"):
            console.print("[red]✗ afl-fuzz not found[/red]")
            return {}

        console.print(Panel(
            f"[bold purple]⬡ RL AGENT — ADAPTIVE SIEGE[/bold purple]\n\n"
            f"[dim]Target   :[/dim] {self.target}\n"
            f"[dim]Corpus   :[/dim] {self.corpus}\n"
            f"[dim]Interval :[/dim] {self.interval}s per strategy\n"
            f"[dim]Duration :[/dim] {self.total_duration}s total\n"
            f"[dim]Epsilon  :[/dim] {self.agent.epsilon:.2f} "
            f"(exploration rate)",
            border_style="purple"
        ))

        start_time = time.time()
        interval_count = 0
        prev_metrics = {
            "paths_found": 0, "saved_crashes": 0,
            "total_execs": 0, "total_tmouts": 0
        }

        try:
            while time.time() - start_time < self.total_duration:
                interval_count += 1
                elapsed = int(time.time() - start_time)

                # Get current state
                curr_metrics = self.stats_reader.get_state_metrics()
                state = self._get_current_state(curr_metrics)

                # Agent selects strategy
                action_idx, strategy = self.agent.select_action(state)

                console.print(
                    f"\n[purple]⬡ Interval {interval_count}[/purple] "
                    f"[dim]({elapsed}s elapsed)[/dim]"
                )
                console.print(
                    f"  Strategy  : [cyan]{strategy}[/cyan] "
                    f"[dim](ε={self.agent.epsilon:.2f})[/dim]"
                )
                console.print(
                    f"  Coverage  : {self.stats_reader.get_coverage_pct():.2f}% · "
                    f"Paths: {curr_metrics['paths_found']} · "
                    f"Crashes: {curr_metrics['saved_crashes']}"
                )

                # Stop previous AFL++ if running
                self._stop_afl()

                # Special handling for LLM-guided strategy
                if strategy == "llm_guided":
                    self._generate_llm_seeds()
                    time.sleep(2)

                # Start AFL++ with selected strategy
                resume = interval_count > 1
                self.afl_process = self._start_afl(strategy, resume=resume)

                # Wait for interval
                time.sleep(self.interval)

                # Read new metrics
                new_metrics = self.stats_reader.get_state_metrics()
                next_state = self._get_current_state(new_metrics)

                # Calculate reward
                reward = self.reward_calc.calculate(
                    prev_paths=prev_metrics["paths_found"],
                    curr_paths=new_metrics["paths_found"],
                    prev_crashes=prev_metrics["saved_crashes"],
                    curr_crashes=new_metrics["saved_crashes"],
                    exec_speed=new_metrics.get("exec_speed", 0),
                    timeouts=new_metrics.get("total_tmouts", 0),
                    interval_seconds=self.interval,
                )

                console.print(
                    f"  Reward    : [{'green' if reward > 0 else 'red'}]{reward}[/]"
                )

                # Update Q-table
                self.agent.update(state, action_idx, reward, next_state)

                # Log episode
                self.episode_log.append({
                    "interval": interval_count,
                    "elapsed": elapsed,
                    "strategy": strategy,
                    "reward": reward,
                    "paths": new_metrics["paths_found"],
                    "crashes": new_metrics["saved_crashes"],
                    "coverage_pct": self.stats_reader.get_coverage_pct(),
                })

                prev_metrics = new_metrics

        except KeyboardInterrupt:
            console.print("\n[yellow]⬡ RL session interrupted by operator.[/yellow]")
        finally:
            self._stop_afl()
            self.agent.total_episodes += 1
            self.agent._save()

        # Generate session report
        summary = self._generate_summary()
        self._save_session_log()

        console.print("\n[bold green]⬡ RL SESSION COMPLETE[/bold green]")
        self.agent.print_stats()

        return summary

    def _generate_summary(self) -> dict:
        """Generate session summary."""
        if not self.episode_log:
            return {}

        final = self.episode_log[-1]
        best_reward_entry = max(self.episode_log, key=lambda x: x["reward"])

        return {
            "intervals": len(self.episode_log),
            "total_paths": final["paths"],
            "total_crashes": final["crashes"],
            "final_coverage": final["coverage_pct"],
            "best_strategy": best_reward_entry["strategy"],
            "best_reward": best_reward_entry["reward"],
            "agent_states_learned": len(self.agent.q_table),
            "epsilon_final": round(self.agent.epsilon, 3),
        }

    def _save_session_log(self):
        """Save episode log as JSON."""
        log_path = self.output / f"rl_session_{int(time.time())}.json"
        with open(log_path, 'w') as f:
            json.dump({
                "session_log": self.episode_log,
                "agent_stats": self.agent.get_strategy_stats(),
            }, f, indent=2)
        console.print(f"[dim]Session log: {log_path}[/dim]")


# ══════════════════════════════════════════════════════════════════════════════
# STANDALONE TEST (without AFL++ — simulated)
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    console.print("\n[bold purple]⬡ RL AGENT — Self Test (Simulated)[/bold purple]\n")

    # Test Q-Learning agent with simulated environment
    agent = QLearningAgent(
        epsilon_start=0.9,
        epsilon_end=0.1,
        epsilon_decay=0.85,
        memory_file="/tmp/test_rl_agent.json"
    )
    encoder = StateEncoder()
    reward_calc = RewardCalculator()

    console.print("[bold]Simulating 20 fuzzing intervals...[/bold]\n")

    # Simulate improving coverage over time
    paths = 0
    crashes = 0
    execs = 0

    for step in range(20):
        # Current state
        state = encoder.encode(
            coverage_pct=min(paths * 2.5, 90),
            total_execs=execs,
            crashes=crashes,
            exec_speed=300 + random.randint(-50, 200),
            cycles_done=step // 3,
        )

        # Agent picks strategy
        action_idx, strategy = agent.select_action(state)

        # Simulate result (some strategies work better)
        if strategy in ["havoc", "llm_guided"]:
            new_paths = random.randint(1, 5)
            new_crashes = 1 if random.random() > 0.85 else 0
        elif strategy in ["bit_flip", "arithmetics"]:
            new_paths = random.randint(0, 3)
            new_crashes = 0
        else:
            new_paths = random.randint(0, 2)
            new_crashes = 0

        execs += 10000
        paths += new_paths
        crashes += new_crashes

        # Next state
        next_state = encoder.encode(
            coverage_pct=min(paths * 2.5, 90),
            total_execs=execs,
            crashes=crashes,
            exec_speed=300 + random.randint(-50, 200),
            cycles_done=(step + 1) // 3,
        )

        # Calculate reward
        reward = reward_calc.calculate(
            prev_paths=paths - new_paths,
            curr_paths=paths,
            prev_crashes=crashes - new_crashes,
            curr_crashes=crashes,
            exec_speed=350,
            timeouts=0,
            interval_seconds=60,
        )

        # Update agent
        agent.update(state, action_idx, reward, next_state)

        mode = "explore" if random.random() < agent.epsilon else "exploit"
        console.print(
            f"  Step {step+1:2d} | [{mode}] [cyan]{strategy:<12}[/cyan] | "
            f"reward={reward:+.1f} | paths={paths} | "
            f"ε={agent.epsilon:.2f}"
        )

    console.print()
    agent.print_stats()

    console.print(f"\n[dim]States learned: {len(agent.q_table)}[/dim]")
    console.print(f"[dim]Best strategy learned: "
                  f"{agent.get_strategy_stats()[0]['strategy']}[/dim]")
    console.print("\n[green]⬡ RL Agent test complete.[/green]\n")
