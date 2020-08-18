/*
    Copyright (C) 2020 Accurics, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

package policyengine

// Engine Policy Engine interface
type Engine interface {
	Init(string) error
	Configure() error
	Evaluate(EngineInput) (EngineOutput, error)
	GetResults() EngineOutput
	Release() error
}

// Policy Policy interface
type Policy interface {
	Load()
	Compile()
}