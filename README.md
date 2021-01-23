# learning-frida
A blog about learning how to use the Frida dynamic instrumentation toolkit with Android

## Building Jekyll locally
```
cd docs
bundle exec jekyll serve
```

More details on [Testing your GitHub Pages site locally with Jekyll](https://help.github.com/en/github/working-with-github-pages/testing-your-github-pages-site-locally-with-jekyll)

## Updating gems / GitHub pages version

* Look at https://pages.github.com/versions/ to see which versions GitHub Pages uses
* If there is a new version of github-pages, update docs/Gemfile with the new version, then run `bundle update github-pages`
* Update docs/Gemfile with new versions for other dependencies if needed.
* Run `bundle update`
* Run `bundle exec jekyll serve` and check that everything seems to be working (running this also updates the Gemfile.lock file)

Useful commands:
* All gems `bundle update`
* One particular gem `bundle update github-pages`