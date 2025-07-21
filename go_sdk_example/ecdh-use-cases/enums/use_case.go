package enums

import "slices"

type UseCase string

var (
	UseCaseImportClearTransportKey UseCase = "ImportClearTransportKey"
	UseCasePINSelect               UseCase = "PINSelect"
)

func (UseCase) Values() []UseCase {
	return []UseCase{
		UseCaseImportClearTransportKey,
		UseCasePINSelect,
	}
}

func (k UseCase) Valid() bool {
	return slices.Contains(k.Values(), k)
}
