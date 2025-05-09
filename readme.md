## Statusphere Go

This is an implementation of the example [ATProto application Statusphere](https://atproto.com/guides/applications) but in Go.

It makes use of an ATProto OAuth [library](https://github.com/haileyok/atproto-oauth-golang). Shout out to [Hailey](https://bsky.app/profile/hailey.at) for implementing a Go OAuth library!

### What is the Statusphere app?
If you haven't read the [ATProto application Statusphere](https://atproto.com/guides/applications) guide about what this is, here is a quick summary.

1: Allows you to log into Bluesky using OAuth.

2: Allows you to post a status (an emoji) which creates a record in your PDS.

3: Shows other users status' when they do the same, even if they are using a different app that this. As long as they are using the statusphere lexicon and NSID then this application will consume those records using Jetstream (firehose) and store them in the local database.

### Running the app

A few environment variables are required to run the app. Use the `example.env` file as a template and store your environment variables in a `.env` file.

* PRIVATEJWKS: This is a private JWKS. You can generate one using the same Go OAuth [library](https://github.com/haileyok/atproto-oauth-golang). Once created, base64 encode it so it's easier to store in your env.
* SESSION_KEY: This can be anything as it's what's used to encrypt session data sent to/from the client.
* HOST: This needs to be a http URL where the server is running. For local dev I suggest using something like [ngrok](https://ngrok.com) to run you app locally and make it accessable externally. This is important for OAuth  as the callback URL configured needs to be a publically accessable.
* DATABASE_MOUNT_PATH: This is where you wish the mysql database to be located.

Run the command `go build -o statuspherego ./cmd/main.go` which will  build the app and then `./statuspherego` to run it.

If running locally I would then run `ngrok http http://localhost:8080` to get your publically accessable URL.

Go to the home page of the app, log in via OAuth and post your status!

### Contributing
This is just a demo app and was mainly for me to learn how to build applications in the ATmosphere and I thought what better way than to use the example statusphere guide but do it in Go.

That being said if you wish to contribute then feel free to fork and PR any improvements you think there can be.
