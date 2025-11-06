// Copyright 2025 Google LLC
// SPDX-License-Identifier: Apache-2.0

package pypi

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"path/filepath"
	re "regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/google/oss-rebuild/internal/gitx"
	"github.com/google/oss-rebuild/internal/uri"
	"github.com/google/oss-rebuild/pkg/rebuild/rebuild"
	pypireg "github.com/google/oss-rebuild/pkg/registry/pypi"
	"github.com/google/oss-rebuild/pkg/vcs/gitscan"
	fuzzy "github.com/paul-mannino/go-fuzzywuzzy"
	"github.com/pelletier/go-toml/v2"
	"github.com/pkg/errors"
	"gopkg.in/ini.v1"
)

// Added to check for specific files
type ZipFileData struct {
	FileName string
	Hash     string
}

type StabilizedCommitValue struct {
	Commit              string
	Timestamp           string
	Files               int  // How many files are getting stabilized / compared?
	Matches             int  // How many files match now?
	TagMatch            bool // Does the commit match any version tag?
	ProjectNameFound    bool // Was the project name found in pyproject.toml or setup.py?
	ProjectVersionFound bool // Was the project version found in pyproject.toml or setup.py?
}

type CfgData struct {
	Name          string
	Version       string
	SetupRequires []string
}

type ProjectMetadata struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type ToolMetadata struct {
	Poetry ProjectMetadata `toml:"poetry"`
}

// Nervous that there are more structures to be found other than what is listed
// I can run a script overnight to look for them
type PyProjectProject struct {
	Metadata ProjectMetadata `toml:"project"`
	Tool     ToolMetadata    `toml:"tool"`
}

// Very similar to BlobHashesFromZip but with file data attached to the hash
func zipHashesWithFiles(zr *zip.Reader) (files []ZipFileData, err error) {
	var f io.ReadCloser
	for _, zf := range zr.File {
		finf := zf.FileInfo()
		if zf.FileInfo().IsDir() {
			continue
		}
		size := int64(zf.UncompressedSize64)
		if size < 0 {
			return nil, errors.Errorf("file exceeds max supported size: %d", zf.UncompressedSize64)
		}
		h := plumbing.NewHasher(plumbing.BlobObject, size)
		f, err = zf.Open()
		if err != nil {
			return nil, err
		}
		if _, err = io.CopyN(h, f, size); err != nil {
			return nil, err
		}
		if err = f.Close(); err != nil {
			return nil, err
		}

		files = append(files, ZipFileData{FileName: finf.Name(), Hash: h.Sum().String()})
	}
	return files, nil
}

// TODO - Remove the similar parsing here and in other places and make a general function for this
// OMG this doesn't actually do any stabilization of the commit files that can be stabilized!!
func stabilizeCommit(commit string, stabilizedHashes []ZipFileData, repository *git.Repository, projectName, projectVersion string) StabilizedCommitValue {
	stabCom := StabilizedCommitValue{
		Commit:   commit,
		Files:    0,
		Matches:  0,
		TagMatch: false,
	}

	// Get the commit from repository
	c, err := repository.CommitObject(plumbing.NewHash(commit))
	if err != nil {
		log.Printf("error retrieving commit object: %v", err)
		return stabCom
	}

	stabCom.Timestamp = c.Committer.When.Format(time.RFC3339Nano)

	fileIterator, err := c.Files()
	if err != nil {
		log.Printf("error retrieving file iterator: %v", err)
		return stabCom
	}

	// Create an in-memory buffer for the zip archive
	var zipBuffer bytes.Buffer
	zipWriter := zip.NewWriter(&zipBuffer)

	// Iterate through all files and add them to the zip
	err = fileIterator.ForEach(func(f *object.File) error {
		// Create a file in the zip archive
		zipFile, err := zipWriter.Create(f.Name)
		if err != nil {
			return fmt.Errorf("error creating zip entry for %s: %v", f.Name, err)
		}

		// Get the file contents
		reader, err := f.Reader()
		if err != nil {
			return fmt.Errorf("error reading file %s: %v", f.Name, err)
		}
		defer reader.Close()

		// Copy the file contents to the zip entry
		_, err = io.Copy(zipFile, reader)
		if err != nil {
			return fmt.Errorf("error writing file %s to zip: %v", f.Name, err)
		}

		// Check for project metadata files
		if strings.Contains(f.Name, "pyproject.toml") || strings.Contains(f.Name, "setup.py") {
			metaReader, err := f.Reader()
			if err != nil {
				return fmt.Errorf("error reading metadata file %s: %v", f.Name, err)
			}
			defer metaReader.Close()
			metaContent, err := io.ReadAll(metaReader)
			if err != nil {
				return fmt.Errorf("error reading metadata content %s: %v", f.Name, err)
			}

			foundData, err := findProjectMetadata(filepath.Base(f.Name), metaContent, projectName, projectVersion)
			if err == nil && foundData {
				if strings.Contains(f.Name, "pyproject.toml") {
					var pyProject PyProjectProject
					if err := toml.Unmarshal(metaContent, &pyProject); err == nil {
						var projectNameFound string
						if pyProject.Metadata.Name != "" {
							projectNameFound = pyProject.Metadata.Name
						} else if pyProject.Tool.Poetry.Name != "" {
							projectNameFound = pyProject.Tool.Poetry.Name
						}

						if projectNameFound != "" {
							fuzzyMatch := fuzzy.Ratio(normalizeName(projectNameFound), normalizeName(projectName))
							if fuzzyMatch > 90 {
								stabCom.ProjectNameFound = true
								if pyProject.Metadata.Version == projectVersion || pyProject.Tool.Poetry.Version == projectVersion {
									stabCom.ProjectVersionFound = true
								}
							}
						}
					}
				} else if strings.Contains(f.Name, "setup.py") {
					// Reuse existing setup.py parsing logic
					setupPyFunctionArgs := gatherSetupPyData(f.Name, metaContent)
					for _, call := range setupPyFunctionArgs.SetupCalls {
						if nameVal, ok := call.Arguments.KeywordArgs["name"]; ok {
							if nameVal.Type == "string" {
								fuzzyMatch := fuzzy.Ratio(normalizeName(nameVal.Value.(string)), normalizeName(projectName))
								if fuzzyMatch > 90 {
									stabCom.ProjectNameFound = true
									if versionVal, ok := call.Arguments.KeywordArgs["version"]; ok {
										if versionVal.Type == "string" && versionVal.Value.(string) == projectVersion {
											stabCom.ProjectVersionFound = true
										}
									}
								}
							}
						}
					}
				} else if strings.Contains(f.Name, "setup.cfg") {
					cfgData := readCfg(metaContent)
					if cfgData.Name != "" {
						fuzzyMatch := fuzzy.Ratio(normalizeName(cfgData.Name), normalizeName(projectName))
						if fuzzyMatch > 90 {
							stabCom.ProjectNameFound = true
							if cfgData.Version == projectVersion {
								stabCom.ProjectVersionFound = true
							}
						}
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		log.Printf("error iterating files: %v", err)
		return stabCom
	}

	// Close the zip writer to finalize the archive
	err = zipWriter.Close()
	if err != nil {
		log.Printf("error closing zip writer: %v", err)
		return stabCom
	}

	// Generate hashes and compare
	zipData := zipBuffer.Bytes()

	// Generate stabilized hashes
	zr, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		log.Printf("error creating zip reader: %v", err)
		return stabCom
	}

	newHashes, err := zipHashesWithFiles(zr)
	if err != nil {
		log.Printf("error calculating hashes: %v", err)
		return stabCom
	}

	// Compare hashes
	for _, hashObj := range stabilizedHashes {
		if strings.HasSuffix(hashObj.FileName, "RECORD") ||
			strings.HasSuffix(hashObj.FileName, "METADATA") ||
			strings.HasSuffix(hashObj.FileName, "WHEEL") {
			continue
		}
		stabCom.Files++
		for _, newHashObj := range newHashes {
			if hashObj.Hash == newHashObj.Hash {
				stabCom.Matches++
				break
			}
		}
	}

	return stabCom
}

// Helper function for stabilizeCommit to check project metadata
// TODO Might be able to replace this with find deep instead? This is basically the same thing?
func findProjectMetadata(fileType string, fileContents []byte, name, version string) (bool, error) {
	if fileType != "pyproject.toml" && fileType != "setup.py" && fileType != "setup.cfg" {
		return false, errors.New("unsupported file type")
	}

	// Leverage existing code for parsing these files
	if fileType == "pyproject.toml" {
		var pyProject PyProjectProject
		if err := toml.Unmarshal(fileContents, &pyProject); err != nil {
			return false, err
		}

		var projectName string
		if pyProject.Metadata.Name != "" {
			projectName = pyProject.Metadata.Name
		} else if pyProject.Tool.Poetry.Name != "" {
			projectName = pyProject.Tool.Poetry.Name
		}

		if projectName != "" {
			fuzzyMatch := fuzzy.Ratio(normalizeName(projectName), normalizeName(name))
			if fuzzyMatch > 90 {
				return true, nil
			}
		}
	} else if fileType == "setup.py" {
		setupPyFunctionArgs := gatherSetupPyData(fileType, fileContents)
		for _, call := range setupPyFunctionArgs.SetupCalls {
			if nameVal, ok := call.Arguments.KeywordArgs["name"]; ok {
				if nameVal.Type == "string" {
					fuzzyMatch := fuzzy.Ratio(normalizeName(nameVal.Value.(string)), normalizeName(name))
					if fuzzyMatch > 90 {
						return true, nil
					}
				}
			}
		}
	} else if fileType == "setup.cfg" {
		cfgData := readCfg(fileContents)
		if cfgData.Name != "" {
			fuzzyMatch := fuzzy.Ratio(normalizeName(cfgData.Name), normalizeName(name))
			// TODO - Might need to adjust this threshold?
			if fuzzyMatch > 90 {
				return true, nil
			}
		}
	}

	return false, nil
}

// Reimplement since it isn't caps
func allTags(repo *git.Repository) (tags []string, err error) {
	ri, err := repo.Tags()
	if err != nil {
		return nil, err
	}
	var ref *plumbing.Reference
	for {
		ref, err = ri.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		tags = append(tags, ref.Name().Short())
	}
	return tags, nil
}

// Add stabilizeCommitRange function - adapted from main.go
func stabilizeCommitRange(commits []string, artifactData []byte, repository *git.Repository, projectName, projectVersion string, uploadTime string, threshold int) ([]StabilizedCommitValue, error) {
	var recheckedCommits []StabilizedCommitValue

	// Create zip reader from artifact data
	zr, err := zip.NewReader(bytes.NewReader(artifactData), int64(len(artifactData)))
	if err != nil {
		return nil, errors.Wrap(err, "creating zip reader")
	}

	// Get hashes with filenames
	stabilizedHashes, err := zipHashesWithFiles(zr)
	if err != nil {
		return nil, errors.Wrap(err, "calculating file hashes")
	}

	// Get the commits of all tags
	taggedCommitStrings := make(map[string]bool)
	tags, err := allTags(repository)
	if err != nil {
		log.Printf("error retrieving tags: %v. Continuing without tags", err)
	}

	for _, tag := range tags {
		tagRes, err := repository.Tag(tag)
		if err != nil {
			log.Printf("error retrieving tag %s: %v. Continuing without this tag", tag, err)
			continue
		}

		var commitHash string
		if t, err := repository.TagObject(tagRes.Hash()); err == nil {
			commitHash = t.Target.String()
		} else {
			commitHash = tagRes.Hash().String()
		}
		taggedCommitStrings[commitHash] = true
	}

	// Evaluate each commit
	var unsortedCommits []StabilizedCommitValue
	for i, commit := range commits {
		if i >= threshold {
			break
		}

		stabilizeResult := stabilizeCommit(commit, stabilizedHashes, repository, projectName, projectVersion)
		if taggedCommitStrings[commit] {
			// If the commit is in the tagged set, mark it as a tag match
			stabilizeResult.TagMatch = true
		}

		unsortedCommits = append(unsortedCommits, stabilizeResult)
	}

	// Sort commits based on multiple criteria using a comparison function
	// Priority (highest to lowest):
	// 1. Number of matches (higher is better - actual file content matching)
	// 2. ProjectVersionFound (exact version match in metadata)
	// 3. ProjectNameFound (name match in metadata)
	// 4. More files compared (more data points) - Might not be as good of a metric as I originally thought
	// 5. TagMatch (commit matches any version tag)
	// 6. Timestamp proximity to uploadTime (closer is better)
	slices.SortFunc(unsortedCommits, func(a, b StabilizedCommitValue) int {
		// 1. Number of matches - highest priority (descending order)
		if a.Matches != b.Matches {
			return b.Matches - a.Matches // negative if b is better
		}

		// 2. ProjectVersionFound - strong metadata signal
		if a.ProjectVersionFound != b.ProjectVersionFound {
			if b.ProjectVersionFound {
				return 1 // b is better
			}
			return -1 // a is better
		}

		// 3. ProjectNameFound
		if a.ProjectNameFound != b.ProjectNameFound {
			if b.ProjectNameFound {
				return 1 // b is better
			}
			return -1 // a is better
		}

		// 4. More files compared - descending order
		if a.Files != b.Files {
			return b.Files - a.Files // negative if b is better
		}

		// 5. TagMatch
		if a.TagMatch != b.TagMatch {
			if b.TagMatch {
				return 1 // b is better
			}
			return -1 // a is better
		}

		// 6. Timestamp proximity to uploadTime (closer is better)
		uploadT, errUpload := time.Parse(time.RFC3339Nano, uploadTime)
		aTime, errA := time.Parse(time.RFC3339Nano, a.Timestamp)
		bTime, errB := time.Parse(time.RFC3339Nano, b.Timestamp)

		if errUpload == nil && errA == nil && errB == nil {
			aDiff := uploadT.Sub(aTime)
			if aDiff < 0 {
				aDiff = -aDiff
			}
			bDiff := uploadT.Sub(bTime)
			if bDiff < 0 {
				bDiff = -bDiff
			}

			if aDiff < bDiff {
				return -1 // a is closer, a is better
			} else if aDiff > bDiff {
				return 1 // b is closer, b is better
			}
		}

		// All criteria equal
		return 0
	})

	recheckedCommits = unsortedCommits
	return recheckedCommits, nil
}

// Add findCommitsInRepo function - combines relevant parts of findCommits from main.go
func findCommitsInRepo(repository *git.Repository) ([]string, error) {
	var commits []string

	// Get all commits
	ci, err := repository.CommitObjects()
	if err != nil {
		return nil, errors.Wrap(err, "getting commit objects")
	}

	err = ci.ForEach(func(c *object.Commit) error {
		commits = append(commits, c.Hash.String())
		return nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "iterating commits")
	}

	if len(commits) == 0 {
		return nil, errors.New("no commits found")
	}

	return commits, nil
}

// searchStrategy interface defines the contract for different commit search strategies
type searchStrategy interface {
	Search(ctx context.Context, r *git.Repository, hashes []string) (closest []string, matched, total int, err error)
}

// findDynamicCommits finds the most matching commits using the dynamic tree search strategy
func findDynamicCommits(repository *git.Repository, artifactData []byte) ([]string, error) {
	// Create a zip reader from the artifact data
	zr, err := zip.NewReader(bytes.NewReader(artifactData), int64(len(artifactData)))
	if err != nil {
		return nil, errors.Wrap(err, "creating zip reader")
	}

	// Extract hashes from the wheel file
	hashesIntermed, err := gitscan.BlobHashesFromZip(zr)
	var hashes []string
	for _, hash := range hashesIntermed {
		hashes = append(hashes, hash.String())
	}
	if err != nil {
		return nil, errors.Wrap(err, "hash calculation")
	}

	// Use dynamic tree search strategy
	strategy := &gitscan.LazyTreeAll{}
	closest, matched, total, err := strategy.Search(context.Background(), repository, hashes)
	if err != nil {
		return nil, errors.Wrap(err, "identity search")
	}

	if matched == 0 {
		return nil, errors.New("no file matches")
	}

	log.Printf("With matches on %d of %d files, best match: %v\n", matched, total, closest)
	return closest, nil
}

// These are commonly used in PyPi metadata to point to the project git repo, using a map as a set.
// Some people capitalize these differently, or add/remove spaces. We normalized to lower, no space.
// This list is ordered, we will choose the first occurrence.
var commonRepoLinks = []string{
	"source",
	"sourcecode",
	"repository",
	"project",
	"github",
}

// There are two places to find the repo:
// 1. In the ProjectURLs (project links)
// 2. Embedded in the description
//
// For 1, there are some ProjectURLs that are very common to use for a repo
// (commonRepoLinks above), so we can break up the ProjectURLs

// Preference:
// where               | known repo host
// -------------------------------------
// project source link | yes
// project source link | no
// "Homepage" link     | yes
// description         | yes
// other project links | yes

func (Rebuilder) InferRepo(ctx context.Context, t rebuild.Target, mux rebuild.RegistryMux) (string, error) {
	project, err := mux.PyPI.Project(ctx, t.Package)
	if err != nil {
		return "", nil
	}
	var linksNamedSource []string
	for _, commonName := range commonRepoLinks {
		for name, url := range project.ProjectURLs {
			if strings.ReplaceAll(strings.ToLower(name), " ", "") == commonName {
				linksNamedSource = append(linksNamedSource, url)
				break
			}
		}
	}
	// Four priority levels:
	// 1. link name is common source link name and it points to a known repo host
	// 1.a prefer "Homepage" if it's a common repo host.
	if repo := uri.FindCommonRepo(project.Homepage); repo != "" {
		return uri.CanonicalizeRepoURI(repo)
	}
	for name, url := range project.ProjectURLs {
		if strings.ReplaceAll(strings.ToLower(name), " ", "") == "homepage" {
			if repo := uri.FindCommonRepo(url); repo != "" {
				return uri.CanonicalizeRepoURI(repo)
			}
		}
	}
	// 1.b use other source links.
	for _, url := range linksNamedSource {
		if repo := uri.FindCommonRepo(url); repo != "" {
			return uri.CanonicalizeRepoURI(repo)
		}
	}
	// 2. link name is common source link name but it doesn't point to a known repo host
	if len(linksNamedSource) != 0 {
		return uri.CanonicalizeRepoURI(linksNamedSource[0])
	}
	// 3. first known repo host link found in the description
	r := uri.FindCommonRepo(project.Description)
	// TODO: Maybe revisit this sponsors logic?
	if r != "" && !strings.Contains(r, "sponsors") {
		return uri.CanonicalizeRepoURI(r)
	}
	// 4. link name is not a common source link name, but points to known repo repo host
	for _, url := range project.ProjectURLs {
		if strings.Contains(url, "sponsors") {
			continue
		}
		if repo := uri.FindCommonRepo(url); repo != "" {
			return uri.CanonicalizeRepoURI(repo)
		}
	}
	return "", errors.New("no git repo")
}

func (Rebuilder) CloneRepo(ctx context.Context, t rebuild.Target, repoURI string, ropt *gitx.RepositoryOptions) (r rebuild.RepoConfig, err error) {
	r.URI = repoURI
	r.Repository, err = rebuild.LoadRepo(ctx, t.Package, ropt.Storer, ropt.Worktree, git.CloneOptions{URL: r.URI, RecurseSubmodules: git.DefaultSubmoduleRecursionDepth})
	switch err {
	case nil:
		return r, nil
	case transport.ErrAuthenticationRequired:
		return r, errors.Errorf("repo invalid or private [repo=%s]", r.URI)
	default:
		return r, errors.Wrapf(err, "clone failed [repo=%s]", r.URI)
	}
}

func parseMultiLineValue(value string) []string {
	lines := strings.Split(value, "\n")
	if len(lines) == 1 {
		// Try a comma as separator if no newlines found
		lines = strings.Split(value, ",")
	}
	var result []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func readCfg(cfgData []byte) CfgData {
	// Load the config file
	cfg, err := ini.LoadSources(ini.LoadOptions{
		IgnoreInlineComment:        true,
		AllowPythonMultilineValues: true,
		SpaceBeforeInlineComment:   true,
	}, cfgData)

	var data CfgData

	if err != nil {
		log.Printf("Failed to load config file: %v\n", err)
		return data
	}

	// Get metadata section
	metadata := cfg.Section("metadata")
	data.Name = metadata.Key("name").String()
	data.Version = metadata.Key("version").String()

	// Get options section
	options := cfg.Section("options")

	// Get setup_requires
	setupRequires := options.Key("setup_requires")
	data.SetupRequires = parseMultiLineValue(setupRequires.String())

	return data
}

func normalizeName(name string) string {
	// Normalizes a package name according to PEP 503.
	normalized := re.MustCompile(`[-_.]+`).ReplaceAllString(name, "-")
	return strings.ToLower(normalized)
}

func goDeepPyProjectOrSetup(fileType string, tree *object.Tree, name, version string) (*object.File, string, error) {
	// Recursively tries to find the correct pyproject.toml for the current package.

	// Does not handle setup.py currently, but will need to eventually
	if fileType != "pyproject.toml" && fileType != "setup.py" && fileType != "setup.cfg" {
		return nil, "", errors.New("filetype is not supported currently")
	}

	type FoundFiles struct {
		Filename       string
		Path           string
		FileObject     *object.File
		MatchThreshold int
	}

	var foundFiles []FoundFiles
	var foundMatchFiles []FoundFiles

	result := tree.Files()
	result.ForEach(func(f *object.File) error {
		if strings.Contains(f.Name, fileType) {
			// log.Println("Found " + fileType + " in subdir: " + f.Name)
			fileContents, err := f.Contents()
			if err != nil {
				return errors.Wrap(err, "Failed to read "+fileType)
			}

			if fileType == "pyproject.toml" {
				var pyProject PyProjectProject
				if err := toml.Unmarshal([]byte(fileContents), &pyProject); err != nil {
					return errors.Wrap(err, "Failed to decode "+fileType)
				}

				var projectName string

				if pyProject.Metadata.Name != "" {
					projectName = pyProject.Metadata.Name
				} else if pyProject.Tool.Poetry.Name != "" {
					projectName = pyProject.Tool.Poetry.Name
				}

				log.Println("Project name found in " + fileType + ": " + projectName + " " + pyProject.Metadata.Version)
				if projectName != "" {
					// log.Println("Found project name in " + fileType + ": " + pyProject.Metadata.Name + " " + pyProject.Metadata.Version)
					fuzzyMatch := fuzzy.Ratio(normalizeName(projectName), normalizeName(name))
					// TODO - Might need to adjust this threshold?
					if fuzzyMatch > 90 {
						log.Println("Matched project name in " + fileType + ": " + projectName)
						foundMatchFiles = append(foundMatchFiles, FoundFiles{Filename: fileType, Path: strings.Replace(f.Name, fileType, "", 1), FileObject: f, MatchThreshold: fuzzyMatch})
					}
				}
			} else if fileType == "setup.py" {
				setupPyFunctionArgs := gatherSetupPyData(f.Name, []byte(fileContents))
				for _, call := range setupPyFunctionArgs.SetupCalls {
					// TODO - Not sure if it can be specified in non kwarg arguments?
					if nameVal, ok := call.Arguments.KeywordArgs["name"]; ok {
						if nameVal.Type == "string" {
							fuzzyMatch := fuzzy.Ratio(normalizeName(nameVal.Value.(string)), normalizeName(name))
							// TODO - Might need to adjust this threshold?
							if fuzzyMatch > 90 {
								log.Println("Matched project name in " + fileType + ": " + nameVal.Value.(string))
								foundMatchFiles = append(foundMatchFiles, FoundFiles{Filename: fileType, Path: strings.Replace(f.Name, fileType, "", 1), FileObject: f, MatchThreshold: fuzzyMatch})
							}
						}
					}
				}
			} else if fileType == "setup.cfg" {
				cfgData := readCfg([]byte(fileContents))
				if cfgData.Name != "" {
					fuzzyMatch := fuzzy.Ratio(normalizeName(cfgData.Name), normalizeName(name))
					// TODO - Might need to adjust this threshold?
					if fuzzyMatch > 90 {
						log.Println("Matched project name in " + fileType + ": " + cfgData.Name)
						foundMatchFiles = append(foundMatchFiles, FoundFiles{Filename: fileType, Path: strings.Replace(f.Name, fileType, "", 1), FileObject: f, MatchThreshold: fuzzyMatch})
					}
				}
			}

			foundFiles = append(foundFiles, FoundFiles{Filename: fileType, Path: strings.Replace(f.Name, fileType, "", 1), FileObject: f})
		}

		return nil
	})

	if len(foundMatchFiles) > 0 && len(foundMatchFiles) == 1 {
		log.Println("Returning " + fileType + " from subdir: " + foundMatchFiles[0].Path)
		return foundMatchFiles[0].FileObject, foundMatchFiles[0].Path, nil
	} else if len(foundMatchFiles) > 1 {
		log.Println("Multiple " + fileType + " files found, returning best match")
		bestMatch := foundMatchFiles[0]
		for _, f := range foundMatchFiles[1:] {
			if f.MatchThreshold > bestMatch.MatchThreshold {
				bestMatch = f
			}
		}
		return bestMatch.FileObject, bestMatch.Path, nil
	} else {
		if len(foundFiles) == 0 {
			log.Println("No " + fileType + " files found in subdirectories.")
			return nil, "", errors.New("no " + fileType + " found in subdirectories")
		} else {
			if fileType == "pyproject.toml" {
				// log.Println("No matching " + fileType + " files found for package: " + name + ". Searching for setup info in the same directories.")
				// Search for setup.py in the same directories
				for _, f := range foundFiles {
					dir := f.Path
					setupPyFile, err := tree.File(dir + "setup.py")
					if err == nil {
						// log.Println("Found setup.py in directory: " + dir)
						setupContents, err := setupPyFile.Contents()
						if err != nil {
							log.Println(errors.Wrap(err, "Failed to read setup.py"))
							continue
						}
						setupInputs := gatherSetupPyData(setupPyFile.Name, []byte(setupContents))
						for _, call := range setupInputs.SetupCalls {
							// TODO - Not sure if it can be specified in non kwarg arguments?
							if nameVal, ok := call.Arguments.KeywordArgs["name"]; ok {
								if nameVal.Type == "string" {
									fuzzyMatch := fuzzy.Ratio(normalizeName(nameVal.Value.(string)), normalizeName(name))
									// TODO - Might need to adjust this threshold?
									if fuzzyMatch > 90 {
										log.Println("Matched project name in " + fileType + ": " + nameVal.Value.(string))
										log.Println("Returning pyproject.toml from directory since setup matches: " + dir)
										return f.FileObject, dir, nil
									}
								}
							}
						}
					}

					// Search for setup.cfg in the same directories
					setupCfgFile, err := tree.File(dir + "setup.cfg")
					if err != nil {
						log.Println(errors.Wrap(err, "Failed to find setup.cfg"))
						continue
					}
					// log.Println("Found setup.cfg in directory: " + dir)
					setupCfgContents, err := setupCfgFile.Contents()
					if err != nil {
						log.Println(errors.Wrap(err, "Failed to read setup.cfg"))
						continue
					}
					cfgData := readCfg([]byte(setupCfgContents))
					if cfgData.Name != "" {
						fuzzyMatch := fuzzy.Ratio(normalizeName(cfgData.Name), normalizeName(name))
						// TODO - Might need to adjust this threshold?
						if fuzzyMatch > 90 {
							log.Println("Matched project name in " + fileType + ": " + cfgData.Name)
							log.Println("Returning pyproject.toml from directory since setup.cfg matches: " + dir)
							return f.FileObject, dir, nil
						}
					}
				}
			} else if fileType == "setup.py" {
				// log.Println("No matching " + fileType + " files found for package: " + name + ". Searching pyproject.toml files in the same directories to find a match.")
				for _, f := range foundFiles {
					dir := f.Path
					pyProjectFile, err := tree.File(dir + "pyproject.toml")
					if err == nil {
						// log.Println("Found pyproject.toml in directory: " + dir)
						pyProjectContents, err := pyProjectFile.Contents()
						if err != nil {
							log.Println(errors.Wrap(err, "Failed to read pyproject.toml"))
							continue
						}

						var pyProject PyProjectProject
						if err := toml.Unmarshal([]byte(pyProjectContents), &pyProject); err != nil {
							continue
						}

						var projectName string

						if pyProject.Metadata.Name != "" {
							projectName = pyProject.Metadata.Name
						} else if pyProject.Tool.Poetry.Name != "" {
							projectName = pyProject.Tool.Poetry.Name
						}

						if projectName != "" {
							// log.Println("Found project name in " + fileType + ": " + projectName + " " + pyProject.Metadata.Version)
							fuzzyMatch := fuzzy.Ratio(normalizeName(projectName), normalizeName(name))
							// TODO - Might need to adjust this threshold?
							if fuzzyMatch > 90 {
								log.Println("Matched project name in " + fileType + ": " + projectName)
								log.Println("Returning setup.py from directory since pyproject.toml matches: " + dir)
								return f.FileObject, dir, nil
							}
						}
					}

					// Search for setup.cfg in the same directories
					setupCfgFile, err := tree.File(dir + "setup.cfg")
					if err != nil {
						log.Println(errors.Wrap(err, "Failed to find setup.cfg"))
						continue
					}
					// log.Println("Found setup.cfg in directory: " + dir)
					setupCfgContents, err := setupCfgFile.Contents()
					if err != nil {
						log.Println(errors.Wrap(err, "Failed to read setup.cfg"))
						continue
					}
					cfgData := readCfg([]byte(setupCfgContents))
					if cfgData.Name != "" {
						fuzzyMatch := fuzzy.Ratio(normalizeName(cfgData.Name), normalizeName(name))
						// TODO - Might need to adjust this threshold?
						if fuzzyMatch > 90 {
							log.Println("Matched project name in " + fileType + ": " + cfgData.Name)
							log.Println("Returning setup.py from directory since setup.cfg matches: " + dir)
							return f.FileObject, dir, nil
						}
					}
				}
			}

			return nil, "", errors.New("no matching " + fileType + " found for package: " + name)
		}
	}
}

func extractSetupRequirements(ctx context.Context, tree *object.Tree, name, version, newDirectory string) ([]string, string, error) {
	var setupReqs []string
	log.Println("Looking for additional reqs in setup.py")
	filePath := newDirectory + "setup.py"
	f, err := tree.File(filePath)
	if err != nil {
		f, newDirectory, err = goDeepPyProjectOrSetup("setup.py", tree, name, version)
		if err != nil {
			return nil, newDirectory, errors.Wrap(err, "Failed to find setup.py")
		}
	}
	setuppyContents, err := f.Contents()
	if err != nil {
		return nil, newDirectory, errors.Wrap(err, "Failed to read setup.py")
	}

	// First try static analysis
	setupInputs := gatherSetupPyData(f.Name, []byte(setuppyContents))
	if len(setupInputs.SetupCalls) != 0 {
		for _, call := range setupInputs.SetupCalls {
			if extractedSetupReqs, ok := call.Arguments.KeywordArgs["setup_requires"]; ok {
				if extractedSetupReqs.Type == "list" {
					for _, v := range extractedSetupReqs.Value.([]ExtractedValue) {
						if v.Type == "string" {
							setupReqs = append(setupReqs, v.Value.(string))
						} else {
							log.Println("Non-string setup requirement found, skipping: " + v.Type)
						}
					}
				}
			}
		}
	}

	return setupReqs, newDirectory, nil
}

func extractPyProjectRequirements(ctx context.Context, tree *object.Tree, name, version string) ([]string, string, error) {
	var reqs []string
	log.Println("Looking for additional reqs in pyproject.toml")
	// TODO: Maybe look for pyproject.toml in subdir?
	f, err := tree.File("pyproject.toml")
	var newDirectory string
	if err != nil {
		f, newDirectory, err = goDeepPyProjectOrSetup("pyproject.toml", tree, name, version)
		if err != nil {
			return nil, newDirectory, errors.Wrap(err, "Failed to find pyproject.toml")
		}
	}
	pyprojContents, err := f.Contents()
	if err != nil {
		return nil, newDirectory, errors.Wrap(err, "Failed to read pyproject.toml")
	}
	type BuildSystem struct {
		Requirements []string `toml:"requires"`
	}
	type PyProject struct {
		Build BuildSystem `toml:"build-system"`
	}
	var pyProject PyProject
	if err := toml.Unmarshal([]byte(pyprojContents), &pyProject); err != nil {
		return nil, newDirectory, errors.Wrap(err, "Failed to decode pyproject.toml")
	}
	for _, r := range pyProject.Build.Requirements {
		// TODO: Some of these requirements are probably already in rbcfg.Requirements, should we skip
		// them? To even know which package we're looking at would require parsing the dependency spec.
		// https://packaging.python.org/en/latest/specifications/dependency-specifiers/#dependency-specifiers
		reqs = append(reqs, strings.ReplaceAll(r, " ", ""))
	}
	log.Println("Added these reqs from pyproject.toml: " + strings.Join(reqs, ", "))
	return reqs, newDirectory, nil
}

// Grabbing more I can make this more efficient later
func getCommitTimestamp(commit string, repository *git.Repository) StabilizedCommitValue {
	stabCom := StabilizedCommitValue{
		Commit:   commit,
		Files:    0,
		Matches:  0,
		TagMatch: false,
	}

	// Get the commit from repository
	c, err := repository.CommitObject(plumbing.NewHash(commit))
	if err != nil {
		log.Printf("error retrieving commit object: %v", err)
		return stabCom
	}

	stabCom.Timestamp = c.Committer.When.Format(time.RFC3339Nano)

	return stabCom
}

func findGitRef(pkg string, version string, rcfg *rebuild.RepoConfig, artifactData []byte, uploadTime string) (string, error) {
	tagHeuristic, err := rebuild.FindTagMatch(pkg, version, rcfg.Repository)
	log.Printf("Version: %s, tag hash: \"%s\"", version, tagHeuristic)
	if err != nil {
		return "", errors.Wrapf(err, "[INTERNAL] tag heuristic error")
	}
	// TODO: Look for the project.toml and check for version number.
	if tagHeuristic == "" {
		// If tag heuristic failed, try to find best matching commit
		log.Printf("No tag found for %s@%s, searching for best matching commit", pkg, version)

		// Just in case
		if len(artifactData) == 0 {
			return "", errors.New("no pure wheel artifact found")
		}

		// Get list of all commits in the repository
		commits, err := findCommitsInRepo(rcfg.Repository)
		if err != nil {
			return "", errors.Wrap(err, "finding ANY commits")
		}

		threshold := 10 // Limit evaluation to first 10 commits

		// Get the best fitting commits
		dynamicCommits, err := findDynamicCommits(rcfg.Repository, artifactData)
		if err != nil {
			log.Printf("Warning: Dynamic commit search failed: %v", err)
			// Continue with all commits if dynamic search fails
			// Uping the threshold because of this
			threshold = 100

			if len(commits) > threshold {
				// sort these commits by closeness to the publication if over the new threshold
				var semiSortedCommitValues []StabilizedCommitValue
				for _, commit := range commits {
					semiSortedCommitValues = append(semiSortedCommitValues, getCommitTimestamp(commit, rcfg.Repository))
				}

				slices.SortFunc(semiSortedCommitValues, func(a, b StabilizedCommitValue) int {
					uploadT, errUpload := time.Parse(time.RFC3339Nano, uploadTime)
					aTime, errA := time.Parse(time.RFC3339Nano, a.Timestamp)
					bTime, errB := time.Parse(time.RFC3339Nano, b.Timestamp)

					if errUpload == nil && errA == nil && errB == nil {
						aDiff := uploadT.Sub(aTime)
						if aDiff < 0 {
							aDiff = -aDiff
						}
						bDiff := uploadT.Sub(bTime)
						if bDiff < 0 {
							bDiff = -bDiff
						}

						if aDiff < bDiff {
							return -1 // a is closer, a is better
						} else if aDiff > bDiff {
							return 1 // b is closer, b is better
						}
					}

					// All criteria equal
					return 0
				})

				var semiSortedCommits []string
				for i, commitValue := range semiSortedCommitValues {
					semiSortedCommits = append(semiSortedCommits, commitValue.Commit)
					if i >= threshold {
						break
					}
				}
				commits = semiSortedCommits
			}
		} else {
			// Use dynamic matches if found
			commits = dynamicCommits
		}

		// Find best matching commit using stabilized commit range
		bestMatches, err := stabilizeCommitRange(commits, artifactData, rcfg.Repository, pkg, version, uploadTime, threshold)
		if err != nil {
			return "", errors.Wrap(err, "finding best commit match")
		}

		if len(bestMatches) == 0 {
			return "", errors.New("no suitable commit found")
		}

		// Use the best match
		bestMatch := bestMatches[0]
		log.Printf("Best matches details: %+v", bestMatches)

		// TODO Potentially have a metric for very low matches cause this should be an indication of the wrong repo
		log.Printf("Found best matching commit: %s (matches: %d/%d, project name found: %v, version found: %v)",
			bestMatch.Commit, bestMatch.Matches, bestMatch.Files, bestMatch.ProjectNameFound, bestMatch.ProjectVersionFound)

		if bestMatch.Files > 5 && bestMatch.Matches > 0 && float64(bestMatch.Matches)/float64(bestMatch.Files) < 0.2 {
			log.Printf("Warning: Low match ratio for best matching commit: %s (matches: %d/%d)", bestMatch.Commit, bestMatch.Matches, bestMatch.Files)
		}

		return bestMatch.Commit, nil
	}

	_, err = rcfg.Repository.CommitObject(plumbing.NewHash(tagHeuristic))
	if err != nil {
		switch err {
		case plumbing.ErrObjectNotFound:
			return "", errors.Errorf("[INTERNAL] Commit ref from tag heuristic not found in repo [repo=%s,ref=%s]", rcfg.URI, tagHeuristic)
		default:
			return "", errors.Wrapf(err, "Checkout failed [repo=%s,ref=%s]", rcfg.URI, tagHeuristic)
		}
	}
	return tagHeuristic, nil
}

// FindPureWheel returns the pure wheel artifact from the given version's releases.
func FindPureWheel(artifacts []pypireg.Artifact) (*pypireg.Artifact, error) {
	for _, r := range artifacts {
		if strings.HasSuffix(r.Filename, "none-any.whl") {
			// Force it to be py3 or py2.py3 for now
			// TODO - Try to build them all
			if !strings.Contains(r.Filename, "py3") {
				continue
			}
			return &r, nil
		}
	}
	return nil, fs.ErrNotExist
}

func inferRequirements(name, version string, zr *zip.Reader) ([]string, error) {
	// Name and version have "-" replaced with "_". See https://packaging.python.org/en/latest/specifications/recording-installed-packages/#the-dist-info-directory
	// TODO: Search for dist-info in the gzip using a regex. It sounds like many tools do varying amounts of normalization on the path name.
	wheelPath := fmt.Sprintf("%s-%s.dist-info/WHEEL", strings.ReplaceAll(name, "-", "_"), strings.ReplaceAll(version, "-", "_"))
	wheel, err := getFile(wheelPath, zr)
	if err != nil {
		return nil, errors.Wrapf(err, "[INTERNAL] Failed to extract upstream %s", wheelPath)
	}
	reqs, err := getGenerator(wheel)
	if err != nil {
		return nil, errors.Wrapf(err, "[INTERNAL] Failed to get upstream generator")
	}
	// Determine setuptools version.
	if slices.ContainsFunc(reqs, func(s string) bool { return strings.HasPrefix(s, "setuptools==") }) {
		// setuptools already set.
		return reqs, nil
	}
	// TODO: Also find this with a regex.
	metadataPath := fmt.Sprintf("%s-%s.dist-info/METADATA", strings.ReplaceAll(name, "-", "_"), strings.ReplaceAll(version, "-", "_"))
	metadata, err := getFile(metadataPath, zr)
	if err != nil {
		return nil, errors.Wrapf(err, "[INTERNAL] Failed to extract upstream dist-info/METADATA")
	}
	switch {
	case !bytes.Contains(metadata, []byte("License-File")):
		// The License-File value was introduced in later versions so this is the
		// most recent version it could be.
		reqs = append(reqs, "setuptools==56.2.0")
	case bytes.Contains(metadata, []byte("Platform: UNKNOWN")):
		// In later versions, unknown platform is omitted. If we see this pattern, it's an older version
		// of setup tools.
		// TODO: There's probably a more specific version where this behavior changed. I just chose the
		// first version I found that worked.
		reqs = append(reqs, "setuptools==57.5.0")
	default:
		reqs = append(reqs, "setuptools==67.7.2")
	}
	return reqs, nil
}

func (Rebuilder) InferStrategy(ctx context.Context, t rebuild.Target, mux rebuild.RegistryMux, rcfg *rebuild.RepoConfig, hint rebuild.Strategy) (rebuild.Strategy, error) {
	name, version := t.Package, t.Version
	release, err := mux.PyPI.Release(ctx, name, version)
	if err != nil {
		return nil, err
	}
	// TODO: support different build types.
	cfg := &PureWheelBuild{}
	var ref, dir string
	lh, ok := hint.(*rebuild.LocationHint)
	if hint != nil && !ok {
		return nil, errors.Errorf("unsupported hint type: %T", hint)
	}

	a, err := FindPureWheel(release.Artifacts)
	if err != nil {
		return cfg, errors.Wrap(err, "finding pure wheel")
	}
	log.Printf("Downloading artifact: %s", a.URL)
	r, err := mux.PyPI.Artifact(ctx, name, version, a.Filename)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, errors.Wrapf(err, "[INTERNAL] Failed to read upstream artifact")
	}

	// Moved since I am now using the wheel to infer information about the commits
	if lh != nil && lh.Ref != "" {
		ref = lh.Ref
		if lh.Dir != "" {
			dir = lh.Dir
		} else {
			dir = rcfg.Dir
		}
	} else {
		ref, err = findGitRef(release.Name, version, rcfg, body, a.UploadTime.Format(time.RFC3339Nano))
		if err != nil {
			return cfg, err
		}
		dir = rcfg.Dir
	}

	zr, err := zip.NewReader(bytes.NewReader(body), a.Size)
	if err != nil {
		return nil, errors.Wrapf(err, "[INTERNAL] Failed to initialize upstream zip reader")
	}
	reqs, err := inferRequirements(release.Name, version, zr)
	if err != nil {
		return cfg, err
	}
	// Extract pyproject.toml requirements.
	{
		commit, err := rcfg.Repository.CommitObject(plumbing.NewHash(ref))
		if err != nil {
			return cfg, errors.Wrapf(err, "Failed to get commit object")
		}
		tree, err := commit.Tree()
		if err != nil {
			return cfg, errors.Wrapf(err, "Failed to get tree")
		}
		if pyprojReqs, newDirectory, err := extractPyProjectRequirements(ctx, tree, name, version); err != nil {
			dir = "<unknown>"
			log.Println(errors.Wrap(err, "Failed to extract reqs from pyproject.toml."))
		} else {
			if newDirectory != "" {
				dir = newDirectory
			}
			existing := make(map[string]bool)
			pkgname := func(req string) string {
				return strings.FieldsFunc(req, func(r rune) bool { return strings.ContainsRune("=<>~! \t", r) })[0]
			}
			for _, req := range reqs {
				existing[pkgname(req)] = true
			}
			for _, newReq := range pyprojReqs {
				if pkg := pkgname(newReq); !existing[pkg] {
					reqs = append(reqs, newReq)
				}
			}
		}

		// Forgot that the unknown part affects the dir capture in the setup reader
		// This fixes that
		resetDir := false
		if dir == "<unknown>" {
			resetDir = true
			dir = ""
		}
		if setupRequirments, newSetupDirectory, err := extractSetupRequirements(ctx, tree, name, version, dir); err != nil {
			if resetDir {
				// Instead of trying a build doomed to fail, fail with better error tracking
				return cfg, errors.Wrap(err, "[INTERNAL] Failed to extract reqs from setup.py or pyproject.toml.")
			}
		} else {
			if newSetupDirectory != "" {
				dir = newSetupDirectory
			}
			existing := make(map[string]bool)
			pkgname := func(req string) string {
				return strings.FieldsFunc(req, func(r rune) bool { return strings.ContainsRune("=<>~! \t", r) })[0]
			}
			for _, req := range reqs {
				existing[pkgname(req)] = true
			}
			for _, newReq := range setupRequirments {
				if pkg := pkgname(newReq); !existing[pkg] {
					reqs = append(reqs, newReq)
				}
			}
		}
	}

	return &PureWheelBuild{
		Location: rebuild.Location{
			Repo: rcfg.URI,
			Dir:  dir,
			Ref:  ref,
		},
		Requirements: reqs,
	}, nil
}

var bdistWheelPat = re.MustCompile(`^Generator: bdist_wheel \(([\d\.]+)\)`)
var setuptoolsPat = re.MustCompile(`^Generator: setuptools \(([\d\.]+)\)`)
var flitPat = re.MustCompile(`^Generator: flit ([\d\.]+)`)
var hatchlingPat = re.MustCompile(`^Generator: hatchling ([\d\.]+)`)

// poetry-core is a subset of poetry. We can treat them as different builders.
var poetryPat = re.MustCompile(`^Generator: poetry ([\d\.]+)`)
var poetryCorePat = re.MustCompile(`^Generator: poetry-core ([\d\.]+)`)

func getGenerator(wheel []byte) (reqs []string, err error) {
	var eol int
	for i := 0; i < len(wheel); i = eol + 1 {
		eol = bytes.IndexRune(wheel[i:], '\n')
		line := wheel[i : i+eol+1]
		sep := bytes.IndexRune(line, ':')
		if sep == -1 {
			// Each line in a WHEEL file has a `key: value` format.
			return nil, errors.New("Unexpected file format")
		}
		key, value := line[:sep], bytes.TrimSpace(line[sep:])
		if bytes.Equal(key, []byte("Generator")) {
			if matches := bdistWheelPat.FindSubmatch(line); matches != nil {
				return []string{"wheel==" + string(matches[1])}, nil
			} else if matches := setuptoolsPat.FindSubmatch(line); matches != nil {
				return []string{"setuptools==" + string(matches[1])}, nil
			} else if matches := flitPat.FindSubmatch(line); matches != nil {
				return []string{"flit_core==" + string(matches[1]), "flit==" + string(matches[1])}, nil
			} else if matches := hatchlingPat.FindSubmatch(line); matches != nil {
				return []string{"hatchling==" + string(matches[1])}, nil
			} else if matches := poetryPat.FindSubmatch(line); matches != nil {
				return []string{"poetry==" + string(matches[1])}, nil
			} else if matches := poetryCorePat.FindSubmatch(line); matches != nil {
				return []string{"poetry-core==" + string(matches[1])}, nil
			} else {
				return nil, errors.Errorf("unsupported generator: %s", value)
			}
		}
	}
	return nil, errors.New("no generator found")
}

func getFile(fname string, zr *zip.Reader) ([]byte, error) {
	for _, f := range zr.File {
		if f.Name == fname {
			fi, err := zr.Open(f.Name)
			if err != nil {
				return nil, err
			}
			return io.ReadAll(fi)
		}
	}
	return nil, fs.ErrNotExist
}
