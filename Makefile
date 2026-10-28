.PHONY: test-affected

# Optional: make test-affected BASE=main HEAD=HEAD
# Without BASE, inspect tracked staged and unstaged changes against HEAD.
test-affected:
	./scripts/affected-tests $(if $(BASE),"$(BASE)" "$(or $(HEAD),HEAD)",) --run
