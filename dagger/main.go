// A generated module for ZigIoUringHttpServer functions
//
// This module has been generated via dagger init and serves as a reference to
// basic module structure as you get started with Dagger.
//
// Two functions have been pre-created. You can modify, delete, or add to them,
// as needed. They demonstrate usage of arguments and return types using simple
// echo and grep commands. The functions can be called from the dagger CLI or
// from one of the SDKs.
//
// The first line in this comment block is a short description line and the
// rest is a long description with more detail on the module's purpose or usage,
// if appropriate. All modules should have a short description.

package main

import (
	"context"
	"dagger/zig-io-uring-http-server/internal/dagger"
)

type ZigIoUringHttpServer struct{}

// Run the tests
func (m *ZigIoUringHttpServer) Test(ctx context.Context,
	// +defaultPath=".."
	src *dagger.Directory,
	// +optional
	platform dagger.Platform,
) (string, error) {

	zigBuilder := dag.Zig().
		Container(dagger.ZigContainerOpts{
			Platform: platform,
		}).
		WithExec([]string{"apt-get", "install", "-y", "libcurl4-openssl-dev"})

	return zigBuilder.
		WithWorkdir("/src").
		WithDirectory("/src", src).
		WithMountedCache("/src/.zig-cache", dag.CacheVolume("src-zig-cache")).
		WithExec([]string{"/app/zig-master/zig", "build", "test", "--summary", "all"}, dagger.ContainerWithExecOpts{
			InsecureRootCapabilities: true,
		}).
		Stdout(ctx)
}
