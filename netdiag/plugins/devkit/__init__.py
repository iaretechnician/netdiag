"""Tocaro Blue devkit checks: Ironman (base), Poseidon, ProteusCore and ApolloCore."""
from netdiag.plugins.devkit import apollo, ironman, poseidon, proteus

MODULES = [ironman.MODULE, poseidon.MODULE, proteus.MODULE, apollo.MODULE]
