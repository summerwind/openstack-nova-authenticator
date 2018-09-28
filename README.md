# OpenStack Nova Authenticator

An authentication server that authenticates an instance using the OpenStack Nova API.

## How does it work?

It works by authenticating the OpenStack instance based on the instance ID and issuing a JWT based token.

The OpenStack instance gets its instance ID from the metadata server or config drive and then calls the authentication endpoint of the Authenticator with the instance ID and the role name indicating to obtain the token.

When the Authenticator receives the instance ID and the role name, it obtains instance information atching the instance ID from OpenStack API. After that, the Authenticator verifies the remote IP address matches the IP address of the instance, and the instance information matches the role defined in the configuration.

If the instance information is valid, the Authenticator will issue a JWT based token.

Since the ID of the OpenStack instance easily leaks out, the Authenticator can limit the authentication based on the number of attempts and the time of instanse startup.

## Install

Download the latest binary from the [Releases](https://github.com/summerwind/openstack-nova-authenticator/releases) page.

## Usage

the Authenticator can be started by specifying the configuration file as follows.

```
$ openstack-nova-authenticator -c config.yml
```

After starting the Authenticator, you can obtain the token in OpenStack instance by requesting as follows.

```
$ curl https://${HOST}/auth -d "instance_id=${INSTANCE_ID}&role=${ROLE_NAME}"
```

## Configuration

Please see `example/config.yml` for the full configuration format.

## Token

The token issued by Authenticator is in JWT format. The claims contained in the token is as follows.

```
{
  // This is the value of 'tokenIssuer' in the configuration file.
  "iss": "https://127.0.0.1:18775",
  // The instance ID of the OpenStack instance.
  "sub": "88802a48-f721-4561-b9d6-4f28cb4eca3a",
  // This value is generated by 'iss' claim and role name.
  "aud": [
    "https://127.0.0.1:18775/roles/web"
  ],
  // The expiration date of the token.
  "exp": 1538125585,
  // The issue date of the token.
  "iat": 1538125525,
  // The instance name of the OpenStack instance.
  "instance_name": "web"
}
```

## Build

If you wish to work on this plugin, you'll first need [Go](https://golang.org), [dep](https://github.com/golang/dep), and [go-task](https://github.com/go-task/task) installed on your machine.

First make sure Go is properly installed, including setting up a [GOPATH](https://golang.org/doc/code.html#GOPATH) environment. Next, clone this repository into `$GOPATH/src/github.com/summerwind/openstack-nova-authenticator`. Then you can install the required Go packages to the vendor directory.

```
$ task vendor
```

To build a development version of this, run `task build`.

```
$ task build
```

To run the tests, invoke `task test`.

```
$ task test
```

You can also see the test coverage report as follows.

```
$ task cover
```


