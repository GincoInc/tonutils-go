/*
This file contain changes specific to gew please edit this file or add a new with gew prefix
*/

package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

func (w *Wallet) BuildUnsignedMessage(ctx context.Context, message *Message, expiry uint64) (*tlb.ExternalMessage, error) {
	return w.PrepareUnsignedMessageForMany(ctx, []*Message{message}, expiry)
}

/*
func (w *Wallet) BuildMessageForMany(ctx context.Context, messages []*Message) (*tlb.ExternalMessage, error) {
	return w.BuildExternalMessageForMany(ctx, messages)
}

func (w *Wallet) BuildExternalMessageForMany(ctx context.Context, messages []*Message) (*tlb.ExternalMessage, error) {
	block, err := w.api.CurrentMasterchainInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get block: %w", err)
	}

	acc, err := w.api.WaitForBlock(block.SeqNo).GetAccount(ctx, block, w.addr)
	if err != nil {
		return nil, fmt.Errorf("failed to get account state: %w", err)
	}

	initialized := acc.IsActive && acc.State.Status == tlb.AccountStatusActive
	return w.PrepareExternalMessageForMany(ctx, !initialized, messages)
}

PrepareExternalMessageForMany - Prepares external message for wallet
can be used directly for offline signing but custom fetchers should be defined in this case
*/

func (w *Wallet) PrepareUnsignedMessageForMany(ctx context.Context, messages []*Message, expiry uint64) (_ *tlb.ExternalMessage, err error) {
	/*
		var stateInit *tlb.StateInit
		if withStateInit {
			stateInit, err = GetStateInit(w.key.Public().(ed25519.PublicKey), w.ver, w.subwallet)
			if err != nil {
				return nil, fmt.Errorf("failed to get state init: %w", err)
			}
		}
	*/

	var msg *cell.Cell
	switch v := w.ver.(type) {
	case Version, ConfigV5R1Beta, ConfigV5R1Final:
		switch v.(type) {
		case ConfigV5R1Beta:
			v = V5R1Beta
		case ConfigV5R1Final:
			v = V5R1Final
		}

		switch v {
		// case V3R2, V3R1, V4R2, V4R1, V5R1Beta, V5R1Final:
		case V5R1Final:
			msg, err = w.spec.(RegularBuilder).BuildUnsignedMessage(ctx, messages, expiry)
			if err != nil {
				return nil, fmt.Errorf("build message err: %w", err)
			}
		/*
			case HighloadV2R2, HighloadV2Verified:
				msg, err = w.spec.(*SpecHighloadV2R2).BuildMessage(ctx, messages)
				if err != nil {
					return nil, fmt.Errorf("build message err: %w", err)
				}
			case HighloadV3:
				return nil, fmt.Errorf("use ConfigHighloadV3 for highload v3 spec")
		*/
		default:
			return nil, fmt.Errorf("send is not yet supported: %w", ErrUnsupportedWalletVersion)
		}
	/*
		case ConfigHighloadV3:
			msg, err = w.spec.(*SpecHighloadV3).BuildMessage(ctx, messages)
			if err != nil {
				return nil, fmt.Errorf("build message err: %w", err)
			}
		case ConfigCustom:
			msg, err = w.spec.(MessageBuilder).BuildMessage(ctx, messages)
			if err != nil {
				return nil, fmt.Errorf("build message err: %w", err)
			}
	*/
	default:
		return nil, fmt.Errorf("send is not yet supported: %w", ErrUnsupportedWalletVersion)
	}

	return &tlb.ExternalMessage{
		DstAddr: w.addr,
		// StateInit: stateInit,
		Body: msg,
	}, nil
}

func (s *SpecV5R1Final) BuildUnsignedMessage(ctx context.Context, messages []*Message, expiry uint64) (_ *cell.Cell, err error) {
	if len(messages) > 255 {
		return nil, errors.New("for this type of wallet max 255 messages can be sent at the same time")
	}

	seq, err := s.seqnoFetcher(ctx, s.wallet.subwallet)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch seqno: %w", err)
	}

	actions, err := packV5Actions(messages)
	if err != nil {
		return nil, fmt.Errorf("failed to build actions: %w", err)
	}

	walletId := V5R1ID{
		NetworkGlobalID: s.config.NetworkGlobalID,
		WorkChain:       s.config.Workchain,
		SubwalletNumber: uint16(s.wallet.subwallet),
		WalletVersion:   0,
	}

	payload := cell.BeginCell().
		MustStoreUInt(0x7369676e, 32).                    // external sign op code
		MustStoreUInt(uint64(walletId.Serialized()), 32). // serialized WalletId
		MustStoreUInt(expiry, 32).                        // validUntil
		// MustStoreUInt(uint64(time.Now().Add(time.Duration(s.messagesTTL)*time.Second).UTC().Unix()), 32). // validUntil
		MustStoreUInt(uint64(seq), 32). // seq (block)
		MustStoreBuilder(actions)       // Action list

	// sign := payload.EndCell().Sign(s.wallet.key)
	// msg := cell.BeginCell().MustStoreBuilder(payload).MustStoreSlice(sign, 512).EndCell()

	return payload.EndCell(), nil
}
