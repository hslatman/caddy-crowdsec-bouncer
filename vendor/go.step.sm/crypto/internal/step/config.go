package step

import (
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// PathEnv defines the name of the environment variable that can overwrite
// the default configuration path.
const PathEnv = "STEPPATH"

// HomeEnv defines the name of the environment variable that can overwrite the
// default home directory.
const HomeEnv = "HOME"

// stepPath will be populated in init() with the proper STEPPATH.
var stepPath string

// homePath will be populated in init() with the proper HOME.
var homePath string

// Path returns the path for the step configuration directory, this is
// defined by the environment variable STEPPATH or if this is not set it will
// default to '$HOME/.step'.
func Path() string {
	return stepPath
}

// Home returns the user home directory using the environment variable HOME or
// the os/user package.
func Home() string {
	return homePath
}

// Abs returns the given path relative to the StepPath if it's not an absolute
// path, relative to the home directory using the special string "~/", or
// relative to the working directory using "./"
//
// Relative paths like 'certs/root_ca.crt' will be converted to
// '$STEPPATH/certs/root_ca.crt', but paths like './certs/root_ca.crt' will be
// relative to the current directory. Home relative paths like
// ~/certs/root_ca.crt will be converted to '$HOME/certs/root_ca.crt'. And
// absolute paths like '/certs/root_ca.crt' will remain the same.
func Abs(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	// Windows accept both \ and /
	slashed := filepath.ToSlash(path)
	switch {
	case strings.HasPrefix(slashed, "~/"):
		return filepath.Join(homePath, path[2:])
	case strings.HasPrefix(slashed, "./"), strings.HasPrefix(slashed, "../"):
		if abs, err := filepath.Abs(path); err == nil {
			return abs
		}
		return path
	default:
		return filepath.Join(stepPath, path)
	}
}

func init() {
	l := log.New(os.Stderr, "", 0)

	// Get home path from environment or from the user object.
	homePath = os.Getenv(HomeEnv)
	if homePath == "" {
		if homePath = getUserHomeDir(); homePath == "" {
			l.Fatalf("Error obtaining home directory, please define environment variable %s.", HomeEnv)
		}
	}

	// Get step path from environment or relative to home.
	stepPath = os.Getenv(PathEnv)
	if stepPath == "" {
		stepPath = filepath.Join(homePath, ".step")
	}

	// cleanup
	homePath = filepath.Clean(homePath)
	stepPath = filepath.Clean(stepPath)
}

func getUserHomeDir() string {
	usr, err := user.Current()
	if err == nil && usr.HomeDir != "" {
		return usr.HomeDir
	}
	return ""
}
