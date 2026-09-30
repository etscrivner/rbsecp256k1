# frozen_string_literal: true

# SPDX-FileCopyrightText: 2026 Eric Scrivner (@etscrivner)
# SPDX-FileCopyrightText: 2026 Afri Blanck (@l5yth)
# SPDX-License-Identifier: Unlicense
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <https://unlicense.org>

require "spec_helper"

# rubyzip before 3.4.0 lets an entry named "../upload_backup/owned.sh" escape
# its extraction directory (GHSA-47m2-wp7j-p9vc, CVE-2026-85396). Only
# extconf.rb uses rubyzip, but as a runtime dependency its requirement decides
# which rubyzip every consumer can resolve, so it must refuse every affected
# release.
RSpec.describe "rbsecp256k1.gemspec" do
  let(:gemspec) do
    Gem::Specification.load(File.expand_path("../../rbsecp256k1.gemspec", __dir__))
  end

  let(:rubyzip) do
    gemspec.runtime_dependencies.find { |dependency| dependency.name == "rubyzip" }.requirement
  end

  it "admits rubyzip 3.4.0, the first release without GHSA-47m2-wp7j-p9vc" do
    expect(rubyzip).to be_satisfied_by(Gem::Version.new("3.4.0"))
  end

  # 2.4.1 is the newest release that 6.0.0's "~> 2.3" admits, 3.2.0 the floor
  # of the "~> 3.2" from PR #85, and 3.3.1 the last affected release.
  %w[2.4.1 3.2.0 3.3.1].each do |version|
    it "refuses rubyzip #{version}, which GHSA-47m2-wp7j-p9vc affects" do
      expect(rubyzip).not_to be_satisfied_by(Gem::Version.new(version))
    end
  end
end
