### Fixed (nightly full matrix)

- Bump the web app to Next.js 15.5.29, which clears the moderate production `npm audit` advisories that failed the web job.
- The project-lock participant test no longer uses 1 second waits for a contender thread, which flaked on loaded runners.
