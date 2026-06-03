# Weather Reporter Skill

This skill fetches the current weather for a given city and formats it
for display. It is a simple read-only helper.

## Usage

Ask the agent: "What's the weather in Boston?"

## Configuration

No configuration is required. The skill uses a public weather API over HTTPS.

## Notes

It is important to provide a city name. Results are cached for five minutes
to avoid hammering the upstream service.
