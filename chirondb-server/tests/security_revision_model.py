#!/usr/bin/env python3
"""Exhaustive sequentially-consistent model of Epoch's admission/drain protocol.
Two old leases represent a query publication and a mutation commit. Every atomic
step can interleave. This models the algorithm, not the entire Rust/transport stack;
concrete Rust tests exercise those boundaries separately. Deliberately weakening
either the second closure check or drain must produce a counterexample.
"""
import json


def explore(second_check=True, drain=True):
    initial = (False, 0, 0, (0, 0))  # closed, active, revoker phase, lease phases
    seen, terminal, violations = set(), 0, []
    stack = [(initial, [])]
    while stack:
        state, trace = stack.pop()
        if state in seen:
            continue
        seen.add(state)
        closed, active, revoke, phases = state
        if revoke == 2 and phases == (6, 6):
            terminal += 1
        successors = []
        if revoke == 0:
            successors.append(((True, active, 1, phases), 'revoke.close'))
        elif revoke == 1 and (active == 0 or not drain):
            successors.append(((closed, active, 2, phases), 'revoke.ack'))
        for i, phase in enumerate(phases):
            updated, count = list(phases), active
            if phase == 0:
                updated[i] = 6 if closed else 1
            elif phase == 1:
                count += 1
                updated[i] = 2
            elif phase == 2:
                updated[i] = 5 if closed and second_check else 3
            elif phase == 3:
                if revoke == 2:
                    violations.append(trace+[f'lease-{i}.publish-or-commit-AFTER-ACK'])
                updated[i] = 4
            elif phase in (4, 5):
                count -= 1
                updated[i] = 6
            else:
                continue
            assert count >= 0
            successors.append(((closed,count,revoke,tuple(updated)),f'lease-{i}.step-{phase}'))
        stack.extend((state,trace+[action]) for state,action in successors)
    return {'states':len(seen),'terminal_states':terminal,'violation_states':len(violations),
            'counterexample':violations[0] if violations else None}


def main():
    valid = explore()
    missing_recheck, missing_drain = explore(second_check=False), explore(drain=False)
    assert valid['terminal_states'] and not valid['violation_states']
    assert missing_recheck['violation_states'] and missing_drain['violation_states']
    print(json.dumps({'contract':valid,'negative_control_without_second_check':missing_recheck,
                      'negative_control_without_drain':missing_drain,
                      'assumptions':['sequentially consistent atomics','a lease is held through the publication/commit event','acknowledgement follows durable policy change','closed epochs never reopen']},indent=2))

if __name__ == '__main__':
    main()
