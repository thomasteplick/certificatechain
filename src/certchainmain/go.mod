module github.com/thomasteplick/certchainmain

go 1.17

require (
	github.com/thomasteplick/certchain v0.0.0
	github.com/thomasteplick/ecdsachain v0.0.0
	github.com/thomasteplick/rsachain v0.0.0
)

replace github.com/thomasteplick/rsachain => ..\rsachain

replace github.com/thomasteplick/certchain => ..\certchain

replace github.com/thomasteplick/ecdsachain => ..\ecdsachain
