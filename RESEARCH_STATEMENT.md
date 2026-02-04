# Research Statement

Vester Imanuel Thacker

## Overview and Research Objective

This research investigates operating system lifecycle management in Unix environments, with a focus on system integrity, auditability, rollback correctness, and long term reproducibility. The objective is to examine how the representation and evolution of operating system state affects system reliability over extended operational lifetimes, particularly in environments where failure recovery, forensic analysis, and configuration assurance are critical.

The work advances a principled approach to system state management that treats operating system state as an immutable, versioned artifact, with all system changes occurring through explicit, auditable transitions.

## Motivation and Problem Context

Modern Unix systems predominantly rely on mutable package and configuration management. Software updates and configuration changes modify the running system in place, causing system state to evolve incrementally over time. While operationally convenient, this approach obscures system identity and complicates assurance.

After repeated updates, it is often not possible to determine precisely which combination of software, configuration, and dependencies produced the current system state. Rollback mechanisms depend on heuristic undo operations rather than restoration of a known state, and failures during upgrade can leave systems partially updated or internally inconsistent. Reconstructing historical states often depends on external repositories and time dependent resolution, weakening reproducibility and traceability.

This research treats these issues as structural consequences of mutable state management rather than as tooling defects.

## Research Hypothesis

The central hypothesis is that operating system state should be managed as an immutable, versioned artifact, and that system change should occur only through explicit transitions that produce new system states. Under this model, each system state has a stable identity, prior states remain intact and selectable, and rollback consists of state selection rather than mutation reversal.

Immutability is treated as an operational requirement that enables deterministic recovery, clear auditing, and reproducible system behavior in long lived systems.

## Methodology

The research defines a system management method in which each system state is represented as a complete artifact capturing the operating system and its configuration. Artifacts are immutable once created. System modification is performed through explicit transitions that consume an existing artifact and produce a new one.

Mutable data such as user files, logs, and runtime state are managed separately from immutable system artifacts to prevent entanglement between system lifecycle and operational data. The method is described independently of any specific packaging format, filesystem, or deployment framework and is intended to be realizable using native operating system primitives.

## Observations and Analysis

Prototype implementations applying this model in Unix environments demonstrate deterministic rollback behavior. Failed upgrades do not corrupt prior system states, and recovery consists of selecting a known good artifact. Auditability improves because each artifact corresponds to a discrete, inspectable system state with an explicit lineage. Reproducibility improves because systems instantiated from the same artifact exhibit identical composition and behavior independent of external repository state.

The analysis identifies tradeoffs, including increased storage requirements and the need for explicit artifact retention policies. Complexity is shifted from mutation handling to artifact lifecycle management rather than eliminated.

## Contributions and Relevance

This research contributes a model level critique of mutable system state management, a falsifiable hypothesis linking immutability to system assurance properties, and a method for managing operating system state as immutable artifacts with explicit transitions. A system manager named Axiom serves as one concrete implementation, but the research is independent of any specific tool.

The results are directly relevant to government, defense, and infrastructure systems where system integrity, auditability, and reliable recovery are mission critical.

## Future Work

Future work includes evaluation across additional Unix variants, development of formal artifact retention and verification policies, and exploration of integration with compliance, security, and system assurance workflows in regulated environments.
